import { decodeProtectedHeader, importJWK, jwtVerify } from 'jose'
import { CAPABILITY_MANIFEST } from './capabilities'
import type { Jwks, WorkerEnv } from './types'

const OAUTH_SCOPE_ALLOW_LIST = new Set<string>(CAPABILITY_MANIFEST.scopes_supported)

export class ApiError extends Error {
  readonly status: number
  readonly error: string

  constructor(status: number, error: string) {
    super(error)
    this.status = status
    this.error = error
  }
}

export interface VerifiedToken {
  userId: string
  email?: string
  scopes: string[]
  rawToken: string
}

export async function verifyRequest(
  request: Request,
  env: WorkerEnv,
  fetchJwks: (url: string) => Promise<Jwks>
): Promise<VerifiedToken> {
  const authorization = request.headers.get('Authorization')
  const token = authorization?.match(/^Bearer\s+(.+)$/i)?.[1]
  if (!token) throw new ApiError(401, 'missing_token')

  try {
    const header = decodeProtectedHeader(token)
    if (header.alg !== 'ES256') throw new Error('Unsupported algorithm.')
    if (typeof header.kid !== 'string') throw new Error('Missing kid.')
    if (header.typ !== 'at+jwt') throw new Error('Unsupported token type.')

    const jwks = await fetchJwks(env.AUTH_JWKS_URL)
    const jwk = jwks.keys.find((k) => k.kid === header.kid)
    if (!jwk) throw new Error('No matching JWK.')

    const key = await importJWK(jwk, 'ES256')
    const { payload } = await jwtVerify(token, key, {
      issuer: env.AUTH_ISSUER,
      audience: env.AUTH_AUDIENCE,
    })

    if (typeof payload.aud !== 'string') throw new Error('Single audience required.')
    if (typeof payload.sub !== 'string') throw new Error('Missing subject.')

    const scopes =
      typeof payload.scope === 'string' ? payload.scope.split(' ').filter(Boolean) : []
    if (scopes.some((s) => !OAUTH_SCOPE_ALLOW_LIST.has(s))) throw new Error('Invalid scope.')

    return {
      userId: payload.sub,
      email: typeof payload.email === 'string' ? payload.email : undefined,
      scopes,
      rawToken: token,
    }
  } catch (error) {
    if (error instanceof ApiError) throw error
    throw new ApiError(401, 'invalid_token')
  }
}
