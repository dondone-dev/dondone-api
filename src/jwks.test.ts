import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { clearJwksCache, fetchJwks } from './jwks'

const JWKS_URL = 'https://auth.dondone.dev/api/jwks'

function jsonResponse(body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { 'content-type': 'application/json' },
  })
}

describe('fetchJwks', () => {
  beforeEach(() => {
    clearJwksCache()
  })
  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('caches within the TTL so a burst of requests hits the network once', async () => {
    const fetchMock = vi
      .spyOn(globalThis, 'fetch')
      .mockResolvedValue(jsonResponse({ keys: [{ kid: 'k1' }] }))

    const first = await fetchJwks(JWKS_URL)
    const second = await fetchJwks(JWKS_URL)

    expect(first).toEqual({ keys: [{ kid: 'k1' }] })
    expect(second).toEqual(first)
    expect(fetchMock).toHaveBeenCalledTimes(1)
  })

  it('sends an abort signal so a hung JWKS endpoint cannot stall the worker', async () => {
    const fetchMock = vi
      .spyOn(globalThis, 'fetch')
      .mockResolvedValue(jsonResponse({ keys: [] }))

    await fetchJwks(JWKS_URL)

    const init = fetchMock.mock.calls[0]?.[1] as RequestInit | undefined
    expect(init?.signal).toBeInstanceOf(AbortSignal)
  })

  it('rejects a non-JSON JWKS response', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response('<html></html>', {
        status: 200,
        headers: { 'content-type': 'text/html' },
      })
    )
    await expect(fetchJwks(JWKS_URL)).rejects.toThrow('Unexpected JWKS content type.')
  })

  it('rejects a malformed JWKS body', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(jsonResponse({ nope: true }))
    await expect(fetchJwks(JWKS_URL)).rejects.toThrow('Malformed JWKS.')
  })

  it('throws when the endpoint returns a non-ok status', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response('', { status: 500 }))
    await expect(fetchJwks(JWKS_URL)).rejects.toThrow('Failed to fetch JWKS.')
  })
})
