import { Hono } from 'hono'
import { cors } from 'hono/cors'
import { verifyRequest, ApiError } from './auth'
import { handleCapabilityMetadata } from './capabilities'
import { fetchJwks } from './jwks'
import { createUsageClient, type CheckAndConsumeResponse } from './usage'
import type { AppDeps, WorkerEnv } from './types'

type HonoEnv = { Bindings: WorkerEnv }

export function createApp(overrides: Partial<AppDeps> = {}) {
  const app = new Hono<HonoEnv>()

  app.use(
    '*',
    cors({
      origin: ['https://auth.dondone.dev', 'https://time.dondone.dev'],
      allowHeaders: ['authorization', 'content-type', 'idempotency-key'],
      allowMethods: ['GET', 'OPTIONS'],
    })
  )

  app.get('/.well-known/oauth-protected-resource', handleCapabilityMetadata)

  app.get('/health', (c) => c.json({ ok: true, service: 'dondone-api' }))

  app.get('/echo', async (c) => {
    try {
      const deps: AppDeps = {
        fetchJwks,
        checkAndConsume: createUsageClient(c.env).checkAndConsume,
        ...overrides,
      }

      const verified = await verifyRequest(c.req.raw, c.env, deps.fetchJwks)

      const idempotencyKey = c.req.header('Idempotency-Key')
      if (
        idempotencyKey &&
        !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(
          idempotencyKey
        )
      ) {
        return c.json({ error: 'invalid_idempotency_key' }, 400)
      }
      const operationId = idempotencyKey ?? crypto.randomUUID()

      let usageResult: CheckAndConsumeResponse
      try {
        usageResult = await withRetry(() =>
          deps.checkAndConsume(
            verified.rawToken,
            {
              service_key: 'api',
              permission_key: 'api:echo',
              operation_id: operationId,
              consume: { daily_calls: 1, request_rate: 1 },
            },
            AbortSignal.timeout(3000)
          )
        )
      } catch (error: unknown) {
        const err = error as { status?: number; error?: string }
        if (err.status === 401) return c.json({ error: 'invalid_token' }, 401)
        if (err.status === 403)
          return c.json({ error: err.error ?? 'insufficient_scope' }, 403)
        if (err.status === 409) return c.json({ error: 'operation_conflict' }, 409)
        if (err.status === 400 || err.status === 422) {
          return c.json(
            { error: err.error ?? (err.status === 422 ? 'service_mismatch' : 'invalid_request') },
            err.status
          )
        }
        return c.json({ error: 'authorization_unavailable' }, 503)
      }

      if (!usageResult.allowed) {
        const status =
          usageResult.reason === 'rate_limited' || usageResult.reason === 'quota_exhausted'
            ? 429
            : 403
        const headers: Record<string, string> = { 'Idempotency-Key': operationId }
        if (status === 429 && usageResult.limits.length > 0) {
          const earliestReset = usageResult.limits
            .map((l) => l.reset_at)
            .filter((r): r is string => r !== null)
            .sort()[0]
          if (earliestReset) {
            const seconds = Math.max(
              1,
              Math.ceil((Date.parse(earliestReset) - Date.now()) / 1000)
            )
            headers['Retry-After'] = String(seconds)
          }
        }
        return c.json(
          {
            error: usageResult.reason,
            limits: usageResult.limits,
          },
          { status, headers }
        )
      }

      return c.json(
        {
          ok: true,
          echo: 'authorized',
          user: {
            id: verified.userId,
            email: verified.email,
          },
          usage: {
            operation_id: usageResult.operation_id,
            policy_key: usageResult.policy_key,
            limits: usageResult.limits,
          },
        },
        { headers: { 'Idempotency-Key': operationId } }
      )
    } catch (error) {
      if (error instanceof ApiError) {
        return c.json({ error: error.error }, error.status as 401 | 403 | 500)
      }
      return c.json({ error: 'internal_error' }, 500)
    }
  })

  return app
}

async function withRetry<T>(fn: () => Promise<T>): Promise<T> {
  try {
    return await fn()
  } catch (error: unknown) {
    const err = error as { status?: number }
    if (err.status && err.status < 500) throw error
    return fn()
  }
}

export default createApp()
