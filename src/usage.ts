import type { WorkerEnv } from './types'

export interface CheckAndConsumeRequest {
  service_key: string
  permission_key: string
  operation_id: string
  consume: Record<string, number>
  context?: Record<string, string | number | boolean | string[]>
}

export interface CheckAndConsumeResponse {
  allowed: boolean
  reason: string
  operation_id: string
  replayed: boolean
  policy_key: string | null
  limits: Array<{
    control_key: string
    limit: number
    used: number
    remaining: number
    reset_at: string | null
  }>
}

// Only surface an upstream error identifier when it looks like a safe, bounded
// error code (snake_case); otherwise fall back to a fixed local vocabulary so
// arbitrary upstream text (internal identifiers, DB errors) never reaches the
// client verbatim.
function safeUpstreamError(value: unknown, fallback: string): string {
  return typeof value === 'string' && /^[a-z][a-z0-9_]{0,63}$/.test(value)
    ? value
    : fallback
}

export function createUsageClient(env: WorkerEnv) {
  const baseUrl = env.AUTH_USAGE_URL

  async function checkAndConsume(
    token: string,
    request: CheckAndConsumeRequest,
    signal?: AbortSignal
  ): Promise<CheckAndConsumeResponse> {
    const response = await fetch(`${baseUrl}/api/usage/check-and-consume`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`,
        'Idempotency-Key': request.operation_id,
      },
      body: JSON.stringify(request),
      signal,
    })

    if (response.status === 401) {
      throw Object.assign(new Error('invalid_token'), { status: 401, error: 'invalid_token' })
    }
    if (response.status === 409) {
      throw Object.assign(new Error('operation_conflict'), { status: 409, error: 'operation_conflict' })
    }
    if (response.status === 400 || response.status === 422) {
      const body = (await response.json().catch(() => ({}))) as Record<string, unknown>
      const fallback = response.status === 422 ? 'service_mismatch' : 'invalid_request'
      const error = safeUpstreamError(body.error, fallback)
      throw Object.assign(new Error(error), { status: response.status, error })
    }
    if (response.status === 403) {
      const body = (await response.json().catch(() => ({}))) as Record<string, unknown>
      const error = safeUpstreamError(body.error, 'insufficient_scope')
      throw Object.assign(new Error(error), { status: 403, error })
    }
    if (!response.ok) {
      throw Object.assign(new Error('authorization_unavailable'), {
        status: 503,
        error: 'authorization_unavailable',
      })
    }

    return (await response.json()) as CheckAndConsumeResponse
  }

  return { checkAndConsume }
}
