import { describe, expect, it, vi, beforeEach } from 'vitest'
import { createUsageClient } from './usage'
import type { WorkerEnv } from './types'

const env: WorkerEnv = {
  AUTH_ISSUER: 'https://auth.dondone.dev',
  AUTH_AUDIENCE: 'https://api.dondone.dev',
  AUTH_JWKS_URL: 'https://auth.dondone.dev/api/jwks',
  AUTH_USAGE_URL: 'https://auth.dondone.dev',
}

const request = {
  service_key: 'api',
  permission_key: 'api:echo',
  operation_id: 'op-abc',
  consume: { daily_calls: 1, request_rate: 1 },
}

beforeEach(() => {
  vi.restoreAllMocks()
})

describe('createUsageClient', () => {
  it('calls check-and-consume with bearer token and idempotency key', async () => {
    const fetchMock = vi.fn(async () =>
      new Response(
        JSON.stringify({
          allowed: true,
          reason: 'allowed',
          operation_id: 'op-abc',
          replayed: false,
          policy_key: 'default',
          limits: [],
        }),
        { status: 200 }
      )
    )
    vi.stubGlobal('fetch', fetchMock)

    const client = createUsageClient(env)
    await client.checkAndConsume('test-token', request)

    expect(fetchMock).toHaveBeenCalledWith(
      'https://auth.dondone.dev/api/usage/check-and-consume',
      expect.objectContaining({
        method: 'POST',
        headers: expect.objectContaining({
          Authorization: 'Bearer test-token',
          'Idempotency-Key': 'op-abc',
        }),
      })
    )
  })

  it('maps 401 to invalid_token', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response('', { status: 401 })))

    const client = createUsageClient(env)
    await expect(client.checkAndConsume('token', request)).rejects.toMatchObject({
      status: 401,
      error: 'invalid_token',
    })
  })

  it('maps 403 to insufficient_scope', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response('', { status: 403 })))

    const client = createUsageClient(env)
    await expect(client.checkAndConsume('token', request)).rejects.toMatchObject({
      status: 403,
      error: 'insufficient_scope',
    })
  })

  it('maps 409 to operation_conflict', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response('', { status: 409 })))

    const client = createUsageClient(env)
    await expect(client.checkAndConsume('token', request)).rejects.toMatchObject({
      status: 409,
      error: 'operation_conflict',
    })
  })

  it('preserves a 422 service_mismatch response', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () =>
        new Response(JSON.stringify({ error: 'service_mismatch' }), {
          status: 422,
          headers: { 'Content-Type': 'application/json' },
        })
      )
    )

    const client = createUsageClient(env)
    await expect(client.checkAndConsume('token', request)).rejects.toMatchObject({
      status: 422,
      error: 'service_mismatch',
    })
  })

  it('maps other errors to authorization_unavailable', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response('', { status: 500 })))

    const client = createUsageClient(env)
    await expect(client.checkAndConsume('token', request)).rejects.toMatchObject({
      status: 503,
      error: 'authorization_unavailable',
    })
  })
})
