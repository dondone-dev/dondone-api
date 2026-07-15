import type { JWK } from 'jose'

export interface WorkerEnv {
  AUTH_ISSUER: string
  AUTH_AUDIENCE: string
  AUTH_JWKS_URL: string
  SUPABASE_URL: string
  SUPABASE_SERVICE_ROLE_KEY: string
  RESOURCE_ACCESS_TOKENS_ENABLED?: string
}

export interface AuthContext {
  userId: string
  email?: string
  permissions: string[]
  tier: 'normal' | 'vip'
}

export interface AuthorizationRecord {
  status: 'active' | 'disabled'
  permissions: string[]
}

export interface Jwks {
  keys: JWK[]
}

export interface AuthSecurityEvent {
  event: 'legacy_access_token_accepted'
  resource: string
  userId: string
}

export interface AppDeps {
  fetchJwks: (env: WorkerEnv) => Promise<Jwks>
  loadAuthorization: (
    env: WorkerEnv,
    userId: string
  ) => Promise<AuthorizationRecord>
  recordSecurityEvent: (event: AuthSecurityEvent) => void
}
