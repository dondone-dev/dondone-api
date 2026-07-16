import type { Context } from 'hono'

export const CAPABILITY_MANIFEST = {
  resource: 'https://api.dondone.dev',
  resource_name: 'Dondone API',
  authorization_servers: ['https://auth.dondone.dev'],
  scopes_supported: ['api:echo'],
  dondone_capabilities: {
    schema_version: 2,
    catalog_version: '2026-07-16.1',
    permissions: [
      {
        key: 'api:echo',
        name: 'Echo API',
        description: 'Call the echo API.',
        usage_controls: [
          {
            key: 'daily_calls',
            name: 'Daily call limit',
            kind: 'quota',
            unit: 'request',
            window: 'calendar_day',
            minimum: 0,
            maximum: 1000000,
          },
          {
            key: 'request_rate',
            name: 'Requests per minute',
            kind: 'rate_limit',
            unit: 'request',
            window_seconds: 60,
            minimum: 0,
            maximum: 10000,
          },
        ],
      },
      {
        key: 'api:tier:vip',
        name: 'VIP Tier',
        description: 'Receive the VIP API response tier.',
      },
    ],
    roles: [
      {
        key: 'caller',
        name: 'Caller',
        description: 'Can call the echo API.',
        permission_keys: ['api:echo'],
      },
      {
        key: 'vip',
        name: 'VIP Caller',
        description: 'Can call the echo API with the VIP response tier.',
        permission_keys: ['api:echo', 'api:tier:vip'],
      },
    ],
  },
} as const

export function handleCapabilityMetadata(c: Context) {
  return c.json(CAPABILITY_MANIFEST, 200, {
    'Cache-Control': 'public, max-age=300',
  })
}
