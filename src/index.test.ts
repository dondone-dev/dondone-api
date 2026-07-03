import { exportJWK, importJWK, SignJWT } from 'jose'
import type { JWK } from 'jose'
import { describe, expect, it } from 'vitest'
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
  }
}

function deps(overrides: Partial<AppDeps> = {}): AppDeps {
  return {
    fetchJwks: async () => ({ keys: [] }),
    loadAuthorization: async () => ({
      status: 'active',
      permissions: ['api:echo'],
    }),
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
          permissions: ['api:echo', 'tier:vip'],
        }),
      })
    ).request('/echo', { headers: { Authorization: `Bearer ${token}` } }, env)

    expect(response.status).toBe(200)
    const body = (await response.json()) as {
      user: { tier: string }
      permissions: string[]
    }
    expect(body.user.tier).toBe('vip')
    expect(body.permissions).toEqual(['api:echo', 'tier:vip'])
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
})
