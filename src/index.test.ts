import { exportJWK, importJWK, SignJWT } from 'jose'
import type { JWK } from 'jose'
import { describe, expect, it, vi } from 'vitest'
import { createApp } from './index'
import type { AppDeps, WorkerEnv } from './types'

const env: WorkerEnv = {
  AUTH_ISSUER: 'https://auth.dondone.dev',
  AUTH_AUDIENCE: 'https://api.dondone.dev',
  AUTH_JWKS_URL: 'https://auth.dondone.dev/api/jwks',
  SUPABASE_URL: 'https://project.supabase.co',
  SUPABASE_SERVICE_ROLE_KEY: 'service-role-key',
}

async function signer() {
  const keyPair = (await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify']
  )) as CryptoKeyPair
  const privateJwk = (await crypto.subtle.exportKey(
    'jwk',
    keyPair.privateKey
  )) as JWK
  const publicJwk = await exportJWK(keyPair.publicKey)
  const key = await importJWK(privateJwk, 'ES256')

  return {
    jwks: {
      keys: [{ ...publicJwk, kid: 'test-key', alg: 'ES256', use: 'sig' }],
    },
    sign: (sub = 'user-123', email = 'user@example.com') =>
      new SignJWT({ email, client_id: 'time', scope: 'api:echo' })
        .setProtectedHeader({ alg: 'ES256', kid: 'test-key', typ: 'JWT' })
        .setIssuer(env.AUTH_ISSUER)
        .setAudience(env.AUTH_AUDIENCE)
        .setSubject(sub)
        .setIssuedAt()
        .setExpirationTime('15m')
        .sign(key),
    signAccessToken: (sub = 'user-123', email = 'user@example.com') =>
      new SignJWT({ email, client_id: 'time', scope: 'api:echo' })
        .setProtectedHeader({ alg: 'ES256', kid: 'test-key', typ: 'at+jwt' })
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
    loadAuthorization: async () => ({
      status: 'active',
      permissions: ['api:echo'],
    }),
    recordSecurityEvent: () => undefined,
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

  it('returns normal tier for an authorized non-VIP user', async () => {
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
        tier: 'normal',
      },
      permissions: ['api:echo'],
    })
  })

  it('returns VIP tier for an authorized VIP user', async () => {
    const testSigner = await signer()
    const token = await testSigner.sign()
    const response = await createApp(
      deps({
        fetchJwks: async () => testSigner.jwks,
        loadAuthorization: async () => ({
          status: 'active',
          permissions: ['api:echo', 'api:tier:vip'],
        }),
      })
    ).request('/echo', { headers: { Authorization: `Bearer ${token}` } }, env)

    expect(response.status).toBe(200)
    const body = (await response.json()) as {
      user: { tier: string }
      permissions: string[]
    }
    expect(body.user.tier).toBe('vip')
    expect(body.permissions).toEqual(['api:echo', 'api:tier:vip'])
  })

  it('treats expired or revoked VIP permission as normal', async () => {
    const testSigner = await signer()
    const token = await testSigner.sign()
    const response = await createApp(
      deps({
        fetchJwks: async () => testSigner.jwks,
        loadAuthorization: async () => ({
          status: 'active',
          permissions: ['api:echo'],
        }),
      })
    ).request('/echo', { headers: { Authorization: `Bearer ${token}` } }, env)

    expect(response.status).toBe(200)
    const body = (await response.json()) as { user: { tier: string } }
    expect(body.user.tier).toBe('normal')
  })

  it('rejects active users without api:echo permission', async () => {
    const testSigner = await signer()
    const token = await testSigner.sign()
    const response = await createApp(
      deps({
        fetchJwks: async () => testSigner.jwks,
        loadAuthorization: async () => ({
          status: 'active',
          permissions: [],
        }),
      })
    ).request('/echo', { headers: { Authorization: `Bearer ${token}` } }, env)

    expect(response.status).toBe(403)
    expect(await response.json()).toEqual({ error: 'permission_denied' })
  })

  it('rejects disabled users', async () => {
    const testSigner = await signer()
    const token = await testSigner.sign()
    const response = await createApp(
      deps({
        fetchJwks: async () => testSigner.jwks,
        loadAuthorization: async () => ({
          status: 'disabled',
          permissions: ['api:echo'],
        }),
      })
    ).request('/echo', { headers: { Authorization: `Bearer ${token}` } }, env)

    expect(response.status).toBe(403)
    expect(await response.json()).toEqual({ error: 'user_disabled' })
  })

  it('accepts at+jwt tokens in resource mode', async () => {
    const testSigner = await signer()
    const token = await testSigner.signAccessToken()
    const resourceEnv = { ...env, RESOURCE_ACCESS_TOKENS_ENABLED: 'true' }
    const response = await createApp(
      deps({ fetchJwks: async () => testSigner.jwks })
    ).request('/echo', { headers: { Authorization: `Bearer ${token}` } }, resourceEnv)

    expect(response.status).toBe(200)
  })

  it('rejects an at+jwt without the required api:echo scope in resource mode', async () => {
    const testSigner = await signer()
    const token = await testSigner.signResourceToken({ scope: '' })
    const resourceEnv = { ...env, RESOURCE_ACCESS_TOKENS_ENABLED: 'true' }
    const response = await createApp(
      deps({ fetchJwks: async () => testSigner.jwks })
    ).request('/echo', { headers: { Authorization: `Bearer ${token}` } }, resourceEnv)

    expect(response.status).toBe(403)
    expect(await response.json()).toEqual({ error: 'insufficient_scope' })
  })

  it('rejects an at+jwt with the wrong scope in resource mode', async () => {
    const testSigner = await signer()
    const token = await testSigner.signResourceToken({ scope: 'api:tier:vip' })
    const resourceEnv = { ...env, RESOURCE_ACCESS_TOKENS_ENABLED: 'true' }
    const response = await createApp(
      deps({ fetchJwks: async () => testSigner.jwks })
    ).request('/echo', { headers: { Authorization: `Bearer ${token}` } }, resourceEnv)

    expect(response.status).toBe(401)
    expect(await response.json()).toEqual({ error: 'invalid_token' })
  })

  it('rejects every token when any scope is absent from the manifest allow-list', async () => {
    const testSigner = await signer()
    const token = await testSigner.signResourceToken({ scope: 'api:echo api:unknown' })
    const resourceEnv = { ...env, RESOURCE_ACCESS_TOKENS_ENABLED: 'true' }
    const response = await createApp(
      deps({ fetchJwks: async () => testSigner.jwks })
    ).request('/echo', { headers: { Authorization: `Bearer ${token}` } }, resourceEnv)

    expect(response.status).toBe(401)
    expect(await response.json()).toEqual({ error: 'invalid_token' })
  })

  it('requires both token scope and the current live grant', async () => {
    const testSigner = await signer()
    const token = await testSigner.signResourceToken({ scope: 'api:echo' })
    const resourceEnv = { ...env, RESOURCE_ACCESS_TOKENS_ENABLED: 'true' }
    const response = await createApp(
      deps({
        fetchJwks: async () => testSigner.jwks,
        loadAuthorization: async () => ({ status: 'active', permissions: [] }),
      })
    ).request('/echo', { headers: { Authorization: `Bearer ${token}` } }, resourceEnv)

    expect(response.status).toBe(403)
    expect(await response.json()).toEqual({ error: 'permission_denied' })
  })

  it('rejects legacy JWT typ when resource tokens are enabled', async () => {
    const testSigner = await signer()
    const token = await testSigner.sign()
    const resourceEnv = { ...env, RESOURCE_ACCESS_TOKENS_ENABLED: 'true' }
    const response = await createApp(
      deps({ fetchJwks: async () => testSigner.jwks })
    ).request('/echo', { headers: { Authorization: `Bearer ${token}` } }, resourceEnv)

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
    const resourceEnv = { ...env, RESOURCE_ACCESS_TOKENS_ENABLED: 'true' }
    const response = await createApp(
      deps({ fetchJwks: async () => testSigner.jwks })
    ).request('/echo', { headers: { Authorization: `Bearer ${token}` } }, resourceEnv)

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

  it('rejects an empty kid before fetching JWKS', async () => {
    const testSigner = await signer()
    const fetchJwks = vi.fn(async () => testSigner.jwks)
    const token = await testSigner.signResourceToken({ kid: '' })
    const response = await createApp(deps({ fetchJwks })).request(
      '/echo',
      { headers: { Authorization: `Bearer ${token}` } },
      env
    )

    expect(response.status).toBe(401)
    expect(fetchJwks).not.toHaveBeenCalled()
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

  it('rejects the wrong token type in resource mode', async () => {
    const testSigner = await signer()
    const token = await testSigner.signResourceToken({ typ: 'JWT' })
    const resourceEnv = { ...env, RESOURCE_ACCESS_TOKENS_ENABLED: 'true' }
    const response = await createApp(
      deps({ fetchJwks: async () => testSigner.jwks })
    ).request('/echo', { headers: { Authorization: `Bearer ${token}` } }, resourceEnv)

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

  it('returns 500 when loadAuthorization throws (fail-closed)', async () => {
    const testSigner = await signer()
    const token = await testSigner.sign()
    const response = await createApp(
      deps({
        fetchJwks: async () => testSigner.jwks,
        loadAuthorization: async () => { throw new Error('Supabase unavailable') },
      })
    ).request('/echo', { headers: { Authorization: `Bearer ${token}` } }, env)

    expect(response.status).toBe(500)
    expect(await response.json()).toEqual({ error: 'internal_error' })
  })

  it('accepts and records legacy token use when resource tokens are disabled', async () => {
    const testSigner = await signer()
    const token = await testSigner.sign()
    const recordSecurityEvent = vi.fn()
    const response = await createApp(
      deps({ fetchJwks: async () => testSigner.jwks, recordSecurityEvent })
    ).request('/echo', { headers: { Authorization: `Bearer ${token}` } }, env)

    expect(response.status).toBe(200)
    expect(recordSecurityEvent).toHaveBeenCalledWith({
      event: 'legacy_access_token_accepted',
      resource: env.AUTH_AUDIENCE,
      userId: 'user-123',
    })
  })
})
