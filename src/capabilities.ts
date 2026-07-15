import type { Context } from 'hono'

export const CAPABILITY_MANIFEST = {
  resource: 'https://api.dondone.dev',
  resource_name: 'Dondone API',
  authorization_servers: ['https://auth.dondone.dev'],
  scopes_supported: ['api:echo'],
  dondone_capabilities: {
    schema_version: 1,
    catalog_version: '2026-07-14.2',
    permissions: [
      { key: 'api:echo', description: 'Call the echo API.' },
      {
        key: 'api:tier:vip',
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
