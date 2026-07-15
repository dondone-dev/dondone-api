import { Hono } from 'hono'
import { cors } from 'hono/cors'
import { authenticateRequest, ApiError } from './auth'
import { handleCapabilityMetadata } from './capabilities'
import { fetchJwks, loadAuthorization } from './supabase'
import type { AppDeps, AuthSecurityEvent, WorkerEnv } from './types'

type HonoEnv = {
  Bindings: WorkerEnv
}

function recordSecurityEvent(event: AuthSecurityEvent): void {
  console.info(JSON.stringify(event))
}

export function createApp(overrides: Partial<AppDeps> = {}) {
  const deps: AppDeps = {
    fetchJwks,
    loadAuthorization,
    recordSecurityEvent,
    ...overrides,
  }
  const app = new Hono<HonoEnv>()

  app.use(
    '*',
    cors({
      origin: ['https://auth.dondone.dev', 'https://time.dondone.dev'],
      allowHeaders: ['authorization', 'content-type'],
      allowMethods: ['GET', 'OPTIONS'],
    })
  )

  app.get('/.well-known/oauth-protected-resource', handleCapabilityMetadata)

  app.get('/health', (c) =>
    c.json({
      ok: true,
      service: 'dondone-api',
    })
  )

  app.get('/echo', async (c) => {
    try {
      const auth = await authenticateRequest(c.req.raw, c.env, deps)
      return c.json({
        ok: true,
        echo: 'authorized',
        user: {
          id: auth.userId,
          email: auth.email,
          tier: auth.tier,
        },
        permissions: auth.permissions,
      })
    } catch (error) {
      if (error instanceof ApiError) {
        return c.json({ error: error.error }, error.status)
      }
      return c.json({ error: 'internal_error' }, 500)
    }
  })

  return app
}

export default createApp()
