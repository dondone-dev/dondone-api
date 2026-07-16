import type { JWK } from 'jose'

export interface WorkerEnv {
  AUTH_ISSUER: string
  AUTH_AUDIENCE: string
  AUTH_JWKS_URL: string
  AUTH_USAGE_URL: string
}

export interface AuthContext {
  userId: string
  email?: string
  scopes: string[]
  tier: 'normal' | 'vip'
}

export interface Jwks {
  keys: JWK[]
}

export interface AppDeps {
  fetchJwks: (jwksUrl: string) => Promise<Jwks>
  checkAndConsume: (
    token: string,
    request: import('./usage').CheckAndConsumeRequest,
    signal?: AbortSignal
  ) => Promise<import('./usage').CheckAndConsumeResponse>
}
