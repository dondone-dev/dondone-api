import { describe, expect, it } from 'vitest'
import { buildEffectivePermissions } from './supabase'

const future = new Date(Date.now() + 60_000).toISOString()
const past = new Date(Date.now() - 60_000).toISOString()

describe('buildEffectivePermissions', () => {
  it('combines active group grants with legacy direct grants', () => {
    const permissions = buildEffectivePermissions({
      direct: [
        { permission_key: 'api:echo', status: 'active', expires_at: null },
        { permission_key: 'legacy:expired', status: 'active', expires_at: past },
      ],
      groups: [
        {
          status: 'active',
          expires_at: future,
          permission_groups: {
            key: 'vip',
            permission_group_permissions: [
              { permissions: { key: 'tier:vip' } },
              { permissions: { key: 'api:echo' } },
            ],
          },
        },
        {
          status: 'revoked',
          expires_at: null,
          permission_groups: {
            key: 'revoked',
            permission_group_permissions: [
              { permissions: { key: 'ai:chat' } },
            ],
          },
        },
      ],
    })

    expect(permissions).toEqual(['api:echo', 'tier:vip'])
  })

  it('ignores expired group grants', () => {
    const permissions = buildEffectivePermissions({
      direct: [],
      groups: [
        {
          status: 'active',
          expires_at: past,
          permission_groups: {
            key: 'vip',
            permission_group_permissions: [
              { permissions: { key: 'tier:vip' } },
            ],
          },
        },
      ],
    })

    expect(permissions).toEqual([])
  })
})
