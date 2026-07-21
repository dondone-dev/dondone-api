import type { JWK } from 'jose'

export interface Jwks {
  keys: JWK[]
}

// The signature header (alg/kid/typ) is checked before verification and is
// attacker-forgeable, so any well-formed request reaches JWKS resolution. A
// per-request outbound fetch would therefore be a DoS-amplification vector
// against the auth server (plus latency and subrequest cost on every legit
// call). Cache the JWKS in module scope with a short TTL; key rotation
// propagates within the TTL window.
const JWKS_TTL_MS = 5 * 60 * 1000
const JWKS_FETCH_TIMEOUT_MS = 3000

interface JwksCacheEntry {
  jwks: Jwks
  expiresAt: number
}

const jwksCache = new Map<string, JwksCacheEntry>()

async function fetchJwksFromNetwork(jwksUrl: string): Promise<Jwks> {
  const response = await fetch(jwksUrl, {
    headers: { accept: 'application/json' },
    signal: AbortSignal.timeout(JWKS_FETCH_TIMEOUT_MS),
  })
  if (!response.ok) {
    throw new Error('Failed to fetch JWKS.')
  }
  const contentType = response.headers.get('content-type') ?? ''
  if (!contentType.toLowerCase().includes('application/json')) {
    throw new Error('Unexpected JWKS content type.')
  }
  const jwks = (await response.json()) as Jwks
  if (!jwks || !Array.isArray(jwks.keys)) {
    throw new Error('Malformed JWKS.')
  }
  return jwks
}

export async function fetchJwks(jwksUrl: string): Promise<Jwks> {
  const cached = jwksCache.get(jwksUrl)
  if (cached && cached.expiresAt > Date.now()) {
    return cached.jwks
  }
  const jwks = await fetchJwksFromNetwork(jwksUrl)
  jwksCache.set(jwksUrl, { jwks, expiresAt: Date.now() + JWKS_TTL_MS })
  return jwks
}

// Exposed for tests to reset the module-level cache between cases.
export function clearJwksCache(): void {
  jwksCache.clear()
}
