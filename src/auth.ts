import { decodeProtectedHeader, importJWK, jwtVerify } from 'jose'
import { CAPABILITY_MANIFEST } from './capabilities'
import type { AppDeps, AuthContext, WorkerEnv } from './types'

const REQUIRED_ECHO_SCOPE = 'api:echo'
const OAUTH_SCOPE_ALLOW_LIST = new Set<string>(CAPABILITY_MANIFEST.scopes_supported)

export class ApiError extends Error {
  readonly status: 401 | 403
  readonly error: string

  constructor(status: 401 | 403, error: string) {
    super(error)
    this.status = status
    this.error = error
  }
}

interface VerifiedToken {
  userId: string
  email?: string
  scopes: string[]
}

export async function authenticateRequest(
  request: Request,
  env: WorkerEnv,
  deps: AppDeps
): Promise<AuthContext> {
  const authorization = request.headers.get('Authorization')
  const token = authorization?.match(/^Bearer\s+(.+)$/i)?.[1]
  if (!token) {
    throw new ApiError(401, 'missing_token')
  }

  const verified = await verifyDondoneToken(token, env, deps)

  if (verified.scopes.some((scope) => !OAUTH_SCOPE_ALLOW_LIST.has(scope))) {
    throw new ApiError(401, 'invalid_token')
  }
  if (!verified.scopes.includes(REQUIRED_ECHO_SCOPE)) {
    throw new ApiError(403, 'insufficient_scope')
  }

  const authorizationRecord = await deps.loadAuthorization(env, verified.userId)
  if (authorizationRecord.status === 'disabled') {
    throw new ApiError(403, 'user_disabled')
  }
  if (!authorizationRecord.permissions.includes('api:echo')) {
    throw new ApiError(403, 'permission_denied')
  }

  const tier = authorizationRecord.permissions.includes('api:tier:vip')
    ? 'vip'
    : 'normal'

  return {
    userId: verified.userId,
    email: verified.email,
    permissions: authorizationRecord.permissions,
    tier,
  }
}

async function verifyDondoneToken(
  token: string,
  env: WorkerEnv,
  deps: AppDeps
): Promise<VerifiedToken> {
  try {
    const header = decodeProtectedHeader(token)

    if (header.alg !== 'ES256') {
      throw new Error('Unsupported algorithm.')
    }
    if (typeof header.kid !== 'string' || header.kid.length === 0) {
      throw new Error('Missing key identifier.')
    }
    if (header.typ !== 'at+jwt') {
      throw new Error('Unsupported token type.')
    }

    const jwks = await deps.fetchJwks(env)
    const jwk = jwks.keys.find((key) => key.kid === header.kid)
    if (!jwk) {
      throw new Error('No matching JWK.')
    }

    const key = await importJWK(jwk, 'ES256')
    const verified = await jwtVerify(token, key, {
      issuer: env.AUTH_ISSUER,
      audience: env.AUTH_AUDIENCE,
    })

    if (
      typeof verified.payload.aud !== 'string' ||
      verified.payload.aud !== env.AUTH_AUDIENCE
    ) {
      throw new Error('Audience must name exactly one resource.')
    }

    if (typeof verified.payload.sub !== 'string') {
      throw new Error('Missing subject.')
    }

    const scopeClaim = verified.payload.scope
    const scopes = typeof scopeClaim === 'string' ? scopeClaim.split(' ').filter(Boolean) : []

    return {
      userId: verified.payload.sub,
      email:
        typeof verified.payload.email === 'string'
          ? verified.payload.email
          : undefined,
      scopes,
    }
  } catch {
    throw new ApiError(401, 'invalid_token')
  }
}
