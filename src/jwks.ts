import type { JWK } from 'jose'

export interface Jwks {
  keys: JWK[]
}

export async function fetchJwks(jwksUrl: string): Promise<Jwks> {
  const response = await fetch(jwksUrl)
  if (!response.ok) {
    throw new Error('Failed to fetch JWKS.')
  }
  return (await response.json()) as Jwks
}
