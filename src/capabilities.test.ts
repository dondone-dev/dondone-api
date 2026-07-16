import { describe, it, expect } from 'vitest'
import { CAPABILITY_MANIFEST } from './capabilities'
import { createApp } from './index'
import type { CheckAndConsumeResponse } from './usage'
import type { WorkerEnv } from './types'

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

describe('CAPABILITY_MANIFEST', () => {
  it('has the correct resource', () => {
    expect(CAPABILITY_MANIFEST.resource).toBe('https://api.dondone.dev')
  })

  it('includes auth.dondone.dev in authorization_servers', () => {
    expect(CAPABILITY_MANIFEST.authorization_servers).toContain('https://auth.dondone.dev')
  })

  it('declares schema_version 2', () => {
    expect(CAPABILITY_MANIFEST.dondone_capabilities.schema_version).toBe(2)
  })

  it('uses the immutable catalog version for this exact manifest content', () => {
    expect(CAPABILITY_MANIFEST.resource_name).toBe('Dondone API')
    expect(CAPABILITY_MANIFEST.dondone_capabilities.catalog_version).toBe('2026-07-16.1')
  })

  it('declares exactly the capabilities implemented by this release', () => {
    expect(CAPABILITY_MANIFEST.dondone_capabilities.permissions).toEqual([
      {
        key: 'api:echo',
        name: 'Echo API',
        description: 'Call the echo API.',
        usage_controls: [
          {
            key: 'daily_calls',
            name: 'Daily call limit',
            kind: 'quota',
            unit: 'request',
            window: 'calendar_day',
            minimum: 0,
            maximum: 1000000,
          },
          {
            key: 'request_rate',
            name: 'Requests per minute',
            kind: 'rate_limit',
            unit: 'request',
            window_seconds: 60,
            minimum: 0,
            maximum: 10000,
          },
        ],
      },
      {
        key: 'api:tier:vip',
        name: 'VIP Tier',
        description: 'Receive the VIP API response tier.',
      },
    ])
    expect(CAPABILITY_MANIFEST.scopes_supported).toEqual(['api:echo'])
  })

  it('has no scopes_supported entry missing from permissions', () => {
    const permKeys = new Set(
      CAPABILITY_MANIFEST.dondone_capabilities.permissions.map((p) => p.key)
    )
    for (const scope of CAPABILITY_MANIFEST.scopes_supported) {
      expect(permKeys.has(scope)).toBe(true)
    }
  })

  it('maps built-in roles only to implemented capabilities', () => {
    expect(CAPABILITY_MANIFEST.dondone_capabilities.roles).toEqual([
      {
        key: 'caller',
        name: 'Caller',
        description: 'Can call the echo API.',
        permission_keys: ['api:echo'],
      },
      {
        key: 'vip',
        name: 'VIP Caller',
        description: 'Can call the echo API with the VIP response tier.',
        permission_keys: ['api:echo', 'api:tier:vip'],
      },
    ])
  })

  it('has unique permission keys', () => {
    const keys = CAPABILITY_MANIFEST.dondone_capabilities.permissions.map((p) => p.key)
    expect(new Set(keys).size).toBe(keys.length)
  })

  it('has role permission_keys referencing declared permissions', () => {
    const permKeys = new Set(
      CAPABILITY_MANIFEST.dondone_capabilities.permissions.map((p) => p.key)
    )
    for (const role of CAPABILITY_MANIFEST.dondone_capabilities.roles) {
      for (const pk of role.permission_keys) {
        expect(permKeys.has(pk)).toBe(true)
      }
    }
  })
})

describe('GET /.well-known/oauth-protected-resource', () => {
  it('returns 200 with correct Content-Type', async () => {
    const app = createApp({
      fetchJwks: async () => ({ keys: [] }),
      checkAndConsume: async () => defaultUsageResult,
    })

    const res = await app.request('/.well-known/oauth-protected-resource', {}, env)
    expect(res.status).toBe(200)
    expect(res.headers.get('Content-Type')).toContain('application/json')
  })

  it('returns the manifest with Cache-Control', async () => {
    const app = createApp({
      fetchJwks: async () => ({ keys: [] }),
      checkAndConsume: async () => defaultUsageResult,
    })

    const res = await app.request('/.well-known/oauth-protected-resource', {}, env)
    const body = (await res.json()) as Record<string, unknown>
    expect(body.resource).toBe('https://api.dondone.dev')
    expect(res.headers.get('Cache-Control')).toContain('max-age=300')
  })

  it('is accessible without authentication', async () => {
    const app = createApp({
      fetchJwks: async () => ({ keys: [] }),
      checkAndConsume: async () => defaultUsageResult,
    })

    const res = await app.request('/.well-known/oauth-protected-resource', {}, env)
    expect(res.status).toBe(200)
  })
})
