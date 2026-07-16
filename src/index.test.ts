import { exportJWK, importJWK, SignJWT } from 'jose'
import type { JWK } from 'jose'
import { describe, expect, it, vi } from 'vitest'
import { createApp } from './index'
import type { AppDeps, WorkerEnv } from './types'
import type { CheckAndConsumeResponse } from './usage'

const env: WorkerEnv = {
  AUTH_ISSUER: 'https://auth.dondone.dev',
  AUTH_AUDIENCE: 'https://api.dondone.dev',
  AUTH_JWKS_URL: 'https://auth.dondone.dev/api/jwks',
  AUTH_USAGE_URL: 'https://auth.dondone.dev',
}

const defaultUsageResult: CheckAndConsumeResponse = {
  allowed: true,
  reason: 'allowed',
  operation_id: 'op-123',
  replayed: false,
  policy_key: 'default',
  limits: [
    {
      control_key: 'daily_calls',
      limit: 1000,
      used: 1,
      remaining: 999,
      reset_at: '2026-07-17T00:00:00.000Z',
    },
    {
      control_key: 'request_rate',
      limit: 60,
      used: 1,
      remaining: 59,
      reset_at: null,
    },
  ],
}

async function signer() {
  const keyPair = (await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify']
  )) as CryptoKeyPair
  const privateJwk = (await crypto.subtle.exportKey('jwk', keyPair.privateKey)) as JWK
  const publicJwk = await exportJWK(keyPair.publicKey)
  const key = await importJWK(privateJwk, 'ES256')

  return {
    jwks: {
      keys: [{ ...publicJwk, kid: 'test-key', alg: 'ES256', use: 'sig' }],
    },
    sign: (sub = 'user-123', email = 'user@example.com') =>
      new SignJWT({ email, client_id: 'time', scope: 'api:echo' })
        .setProtectedHeader({ alg: 'ES256', kid: 'test-key', typ: 'at+jwt' })
        .setIssuer(env.AUTH_ISSUER)
        .setAudience(env.AUTH_AUDIENCE)
        .setSubject(sub)
        .setIssuedAt()
        .setExpirationTime('15m')
        .sign(key),
    signLegacyToken: (sub = 'user-123', email = 'user@example.com') =>
      new SignJWT({ email, client_id: 'time', scope: 'api:echo' })
        .setProtectedHeader({ alg: 'ES256', kid: 'test-key', typ: 'JWT' })
        .setIssuer(env.AUTH_ISSUER)
        .setAudience(env.AUTH_AUDIENCE)
        .setSubject(sub)
        .setIssuedAt()
        .setExpirationTime('15m')
        .sign(key),
    signWrongAudience: (sub = 'user-123') =>
      new SignJWT({ client_id: 'time', scope: 'api:echo' })
        .setProtectedHeader({ alg: 'ES256', kid: 'test-key', typ: 'at+jwt' })
        .setIssuer(env.AUTH_ISSUER)
        .setAudience('https://other.dondone.dev')
        .setSubject(sub)
        .setIssuedAt()
        .setExpirationTime('15m')
        .sign(key),
    signResourceToken: ({
      audience = env.AUTH_AUDIENCE,
      kid = 'test-key',
      scope = 'api:echo',
      typ = 'at+jwt',
    }: {
      audience?: string | string[]
      kid?: string | null
      scope?: string
      typ?: string | null
    } = {}) => {
      const jwt = new SignJWT({
        email: 'user@example.com',
        client_id: 'time',
        scope,
      })
      jwt.setProtectedHeader({
        alg: 'ES256',
        ...(kid === null ? {} : { kid }),
        ...(typ === null ? {} : { typ }),
      })
      jwt
        .setIssuer(env.AUTH_ISSUER)
        .setAudience(audience)
        .setSubject('user-123')
        .setIssuedAt()
        .setExpirationTime('15m')
      return jwt.sign(key)
    },
  }
}

function deps(overrides: Partial<AppDeps> = {}): AppDeps {
  return {
    fetchJwks: async () => ({ keys: [] }),
    checkAndConsume: async () => defaultUsageResult,
    ...overrides,
  }
}

describe('dondone-api', () => {
  it('returns health status', async () => {
    const response = await createApp().request('/health', {}, env)

    expect(response.status).toBe(200)
    expect(await response.json()).toEqual({
      ok: true,
      service: 'dondone-api',
    })
  })

  it('rejects echo requests without a bearer token', async () => {
    const response = await createApp(deps()).request('/echo', {}, env)

    expect(response.status).toBe(401)
    expect(await response.json()).toEqual({ error: 'missing_token' })
  })

  it('rejects echo requests with an invalid JWT', async () => {
    const response = await createApp(deps()).request(
      '/echo',
      { headers: { Authorization: 'Bearer not-a-jwt' } },
      env
    )

    expect(response.status).toBe(401)
    expect(await response.json()).toEqual({ error: 'invalid_token' })
  })

  it('returns authorized echo with usage info for a valid token', async () => {
    const testSigner = await signer()
    const token = await testSigner.sign()
    const response = await createApp(
      deps({ fetchJwks: async () => testSigner.jwks })
    ).request('/echo', { headers: { Authorization: `Bearer ${token}` } }, env)

    expect(response.status).toBe(200)
    expect(await response.json()).toEqual({
      ok: true,
      echo: 'authorized',
      user: {
        id: 'user-123',
        email: 'user@example.com',
      },
      usage: {
        operation_id: 'op-123',
        policy_key: 'default',
        limits: defaultUsageResult.limits,
      },
    })
  })

  it('forwards the client-provided Idempotency-Key as operation_id', async () => {
    const testSigner = await signer()
    const token = await testSigner.sign()
    const operationId = '22222222-2222-4222-8222-222222222222'
    const checkAndConsume = vi.fn(async () => defaultUsageResult)
    await createApp(
      deps({
        fetchJwks: async () => testSigner.jwks,
        checkAndConsume,
      })
    ).request(
      '/echo',
      {
        headers: {
          Authorization: `Bearer ${token}`,
          'Idempotency-Key': operationId,
        },
      },
      env
    )

    expect(checkAndConsume).toHaveBeenCalledWith(
      token,
      expect.objectContaining({ operation_id: operationId }),
      expect.any(AbortSignal)
    )
  })

  it('rejects when usage API returns insufficient_scope', async () => {
    const testSigner = await signer()
    const token = await testSigner.sign()
    const response = await createApp(
      deps({
        fetchJwks: async () => testSigner.jwks,
        checkAndConsume: async () => {
          throw Object.assign(new Error('insufficient_scope'), {
            status: 403,
            error: 'insufficient_scope',
          })
        },
      })
    ).request('/echo', { headers: { Authorization: `Bearer ${token}` } }, env)

    expect(response.status).toBe(403)
    expect(await response.json()).toEqual({ error: 'insufficient_scope' })
  })

  it('rejects when usage API denies with rate_limited', async () => {
    const testSigner = await signer()
    const token = await testSigner.sign()
    const response = await createApp(
      deps({
        fetchJwks: async () => testSigner.jwks,
        checkAndConsume: async () => ({
          ...defaultUsageResult,
          allowed: false,
          reason: 'rate_limited',
        }),
      })
    ).request('/echo', { headers: { Authorization: `Bearer ${token}` } }, env)

    expect(response.status).toBe(429)
    expect(response.headers.get('Idempotency-Key')).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i
    )
    const body = (await response.json()) as { error: string; limits: unknown[] }
    expect(body.error).toBe('rate_limited')
    expect(body.limits).toEqual(defaultUsageResult.limits)
  })

  it('rejects when usage API denies with quota_exhausted', async () => {
    const testSigner = await signer()
    const token = await testSigner.sign()
    const response = await createApp(
      deps({
        fetchJwks: async () => testSigner.jwks,
        checkAndConsume: async () => ({
          ...defaultUsageResult,
          allowed: false,
          reason: 'quota_exhausted',
        }),
      })
    ).request('/echo', { headers: { Authorization: `Bearer ${token}` } }, env)

    expect(response.status).toBe(429)
    expect((await response.json()) as { error: string }).toEqual({
      error: 'quota_exhausted',
      limits: defaultUsageResult.limits,
    })
  })

  it('rejects when usage API returns operation_conflict', async () => {
    const testSigner = await signer()
    const token = await testSigner.sign()
    const response = await createApp(
      deps({
        fetchJwks: async () => testSigner.jwks,
        checkAndConsume: async () => {
          throw Object.assign(new Error('operation_conflict'), {
            status: 409,
            error: 'operation_conflict',
          })
        },
      })
    ).request('/echo', { headers: { Authorization: `Bearer ${token}` } }, env)

    expect(response.status).toBe(409)
    expect(await response.json()).toEqual({ error: 'operation_conflict' })
  })

  it('returns 503 when usage service is unavailable', async () => {
    const testSigner = await signer()
    const token = await testSigner.sign()
    const response = await createApp(
      deps({
        fetchJwks: async () => testSigner.jwks,
        checkAndConsume: async () => {
          throw Object.assign(new Error('usage_service_unavailable'), {
            status: 503,
            error: 'usage_service_unavailable',
          })
        },
      })
    ).request('/echo', { headers: { Authorization: `Bearer ${token}` } }, env)

    expect(response.status).toBe(503)
    expect(await response.json()).toEqual({ error: 'authorization_unavailable' })
  })

  it('accepts at+jwt tokens', async () => {
    const testSigner = await signer()
    const token = await testSigner.sign()
    const response = await createApp(
      deps({ fetchJwks: async () => testSigner.jwks })
    ).request('/echo', { headers: { Authorization: `Bearer ${token}` } }, env)

    expect(response.status).toBe(200)
  })

  it('rejects an at+jwt with the wrong scope', async () => {
    const testSigner = await signer()
    const token = await testSigner.signResourceToken({ scope: 'api:tier:vip' })
    const response = await createApp(
      deps({ fetchJwks: async () => testSigner.jwks })
    ).request('/echo', { headers: { Authorization: `Bearer ${token}` } }, env)

    expect(response.status).toBe(401)
    expect(await response.json()).toEqual({ error: 'invalid_token' })
  })

  it('rejects every token when any scope is absent from the manifest allow-list', async () => {
    const testSigner = await signer()
    const token = await testSigner.signResourceToken({ scope: 'api:echo api:unknown' })
    const response = await createApp(
      deps({ fetchJwks: async () => testSigner.jwks })
    ).request('/echo', { headers: { Authorization: `Bearer ${token}` } }, env)

    expect(response.status).toBe(401)
    expect(await response.json()).toEqual({ error: 'invalid_token' })
  })

  it('rejects legacy JWT typ', async () => {
    const testSigner = await signer()
    const token = await testSigner.signLegacyToken()
    const response = await createApp(
      deps({ fetchJwks: async () => testSigner.jwks })
    ).request('/echo', { headers: { Authorization: `Bearer ${token}` } }, env)

    expect(response.status).toBe(401)
    expect(await response.json()).toEqual({ error: 'invalid_token' })
  })

  it('rejects token with wrong audience', async () => {
    const testSigner = await signer()
    const token = await testSigner.signWrongAudience()
    const response = await createApp(
      deps({ fetchJwks: async () => testSigner.jwks })
    ).request('/echo', { headers: { Authorization: `Bearer ${token}` } }, env)

    expect(response.status).toBe(401)
    expect(await response.json()).toEqual({ error: 'invalid_token' })
  })

  it('rejects a multi-audience token even when the API resource is included', async () => {
    const testSigner = await signer()
    const token = await testSigner.signResourceToken({
      audience: [env.AUTH_AUDIENCE, 'https://ai.dondone.dev'],
    })
    const response = await createApp(
      deps({ fetchJwks: async () => testSigner.jwks })
    ).request('/echo', { headers: { Authorization: `Bearer ${token}` } }, env)

    expect(response.status).toBe(401)
    expect(await response.json()).toEqual({ error: 'invalid_token' })
  })

  it('rejects a token without kid', async () => {
    const testSigner = await signer()
    const token = await testSigner.signResourceToken({ kid: null })
    const response = await createApp(
      deps({ fetchJwks: async () => testSigner.jwks })
    ).request('/echo', { headers: { Authorization: `Bearer ${token}` } }, env)

    expect(response.status).toBe(401)
    expect(await response.json()).toEqual({ error: 'invalid_token' })
  })

  it('rejects an empty kid', async () => {
    const testSigner = await signer()
    const fetchJwks = vi.fn(async () => testSigner.jwks)
    const token = await testSigner.signResourceToken({ kid: '' })
    const response = await createApp(deps({ fetchJwks })).request(
      '/echo',
      { headers: { Authorization: `Bearer ${token}` } },
      env
    )

    expect(response.status).toBe(401)
    expect(fetchJwks).toHaveBeenCalled()
  })

  it('rejects a kid that does not exactly match a published key', async () => {
    const testSigner = await signer()
    const token = await testSigner.signResourceToken({ kid: 'test-key ' })
    const response = await createApp(
      deps({ fetchJwks: async () => testSigner.jwks })
    ).request('/echo', { headers: { Authorization: `Bearer ${token}` } }, env)

    expect(response.status).toBe(401)
    expect(await response.json()).toEqual({ error: 'invalid_token' })
  })

  it('rejects an unsupported signing algorithm before fetching JWKS', async () => {
    const fetchJwks = vi.fn(async () => ({ keys: [] }))
    const token = await new SignJWT({ scope: 'api:echo' })
      .setProtectedHeader({ alg: 'HS256', kid: 'test-key', typ: 'at+jwt' })
      .setIssuer(env.AUTH_ISSUER)
      .setAudience(env.AUTH_AUDIENCE)
      .setSubject('user-123')
      .setExpirationTime('15m')
      .sign(new TextEncoder().encode('01234567890123456789012345678901'))

    const response = await createApp(deps({ fetchJwks })).request(
      '/echo',
      { headers: { Authorization: `Bearer ${token}` } },
      env
    )

    expect(response.status).toBe(401)
    expect(fetchJwks).not.toHaveBeenCalled()
  })

  it('rejects the wrong token type', async () => {
    const testSigner = await signer()
    const token = await testSigner.signResourceToken({ typ: 'JWT' })
    const response = await createApp(
      deps({ fetchJwks: async () => testSigner.jwks })
    ).request('/echo', { headers: { Authorization: `Bearer ${token}` } }, env)

    expect(response.status).toBe(401)
    expect(await response.json()).toEqual({ error: 'invalid_token' })
  })

  it('rejects a token without typ even when resource mode is disabled', async () => {
    const testSigner = await signer()
    const token = await testSigner.signResourceToken({ typ: null })
    const response = await createApp(
      deps({ fetchJwks: async () => testSigner.jwks })
    ).request('/echo', { headers: { Authorization: `Bearer ${token}` } }, env)

    expect(response.status).toBe(401)
    expect(await response.json()).toEqual({ error: 'invalid_token' })
  })

  it('rejects an unknown typ even when resource mode is disabled', async () => {
    const testSigner = await signer()
    const token = await testSigner.signResourceToken({ typ: 'application/jwt' })
    const response = await createApp(
      deps({ fetchJwks: async () => testSigner.jwks })
    ).request('/echo', { headers: { Authorization: `Bearer ${token}` } }, env)

    expect(response.status).toBe(401)
    expect(await response.json()).toEqual({ error: 'invalid_token' })
  })

  it('rejects legacy JWT tokens without a rollout flag', async () => {
    const testSigner = await signer()
    const token = await testSigner.signLegacyToken()
    const response = await createApp(
      deps({ fetchJwks: async () => testSigner.jwks })
    ).request('/echo', { headers: { Authorization: `Bearer ${token}` } }, env)

    expect(response.status).toBe(401)
    expect(await response.json()).toEqual({ error: 'invalid_token' })
  })
})
