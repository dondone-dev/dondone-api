import { beforeEach, describe, expect, it, vi } from 'vitest'

const createClientMock = vi.hoisted(() => vi.fn())

vi.mock('@supabase/supabase-js', () => ({ createClient: createClientMock }))

import { buildEffectivePermissions, loadAuthorization } from './supabase'
import type { WorkerEnv } from './types'

const future = new Date(Date.now() + 60_000).toISOString()
const past = new Date(Date.now() - 60_000).toISOString()

const env: WorkerEnv = {
  AUTH_ISSUER: 'https://auth.dondone.dev',
  AUTH_AUDIENCE: 'https://api.dondone.dev',
  AUTH_JWKS_URL: 'https://auth.dondone.dev/api/jwks',
  SUPABASE_URL: 'https://project.supabase.co',
  SUPABASE_SERVICE_ROLE_KEY: 'service-role-key',
}

function queryResult(result: unknown, terminal: 'maybeSingle' | 'returns') {
  const query = {
    select: vi.fn(),
    eq: vi.fn(),
    maybeSingle: vi.fn(),
    returns: vi.fn(),
  }
  query.select.mockReturnValue(query)
  query.eq.mockReturnValue(query)
  query.maybeSingle.mockResolvedValue(terminal === 'maybeSingle' ? result : undefined)
  query.returns.mockResolvedValue(terminal === 'returns' ? result : undefined)
  return query
}

function mockAuthorizationQueries(results: {
  profile: unknown
  direct?: unknown
  groups?: unknown
}) {
  const queries = {
    profiles: queryResult(results.profile, 'maybeSingle'),
    user_permissions: queryResult(
      results.direct ?? { data: [], error: null },
      'returns'
    ),
    user_permission_groups: queryResult(
      results.groups ?? { data: [], error: null },
      'returns'
    ),
  }
  createClientMock.mockReturnValue({
    from: (table: keyof typeof queries) => queries[table],
  })
  return queries
}

beforeEach(() => {
  createClientMock.mockReset()
})

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
            status: 'active',
            permission_group_permissions: [
              { permissions: { key: 'api:tier:vip' } },
              { permissions: { key: 'api:echo' } },
            ],
          },
        },
        {
          status: 'revoked',
          expires_at: null,
          permission_groups: {
            key: 'revoked',
            status: 'active',
            permission_group_permissions: [
              { permissions: { key: 'ai:chat' } },
            ],
          },
        },
      ],
    })

    expect(permissions).toEqual(['api:echo', 'api:tier:vip'])
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
            status: 'active',
            permission_group_permissions: [
              { permissions: { key: 'api:tier:vip' } },
            ],
          },
        },
      ],
    })

    expect(permissions).toEqual([])
  })
})

describe('loadAuthorization fail-closed adapter', () => {
  it('fails when the profile query errors', async () => {
    mockAuthorizationQueries({
      profile: { data: null, error: { message: 'profile unavailable' } },
    })

    await expect(loadAuthorization(env, 'user-123')).rejects.toThrow(
      'Profile query failed: profile unavailable'
    )
  })

  it('treats a missing profile as disabled without reading grants', async () => {
    const queries = mockAuthorizationQueries({
      profile: { data: null, error: null },
    })

    await expect(loadAuthorization(env, 'user-123')).resolves.toEqual({
      status: 'disabled',
      permissions: [],
    })
    expect(queries.user_permissions.select).not.toHaveBeenCalled()
    expect(queries.user_permission_groups.select).not.toHaveBeenCalled()
  })

  it('fails when the direct permission query errors', async () => {
    mockAuthorizationQueries({
      profile: { data: { status: 'active' }, error: null },
      direct: { data: null, error: { message: 'direct unavailable' } },
    })

    await expect(loadAuthorization(env, 'user-123')).rejects.toThrow(
      'Permission query failed: direct unavailable'
    )
  })

  it('fails when the group permission query errors', async () => {
    mockAuthorizationQueries({
      profile: { data: { status: 'active' }, error: null },
      groups: { data: null, error: { message: 'groups unavailable' } },
    })

    await expect(loadAuthorization(env, 'user-123')).rejects.toThrow(
      'Permission group query failed: groups unavailable'
    )
  })

  it('does not grant permissions from a disabled permission group', async () => {
    mockAuthorizationQueries({
      profile: { data: { status: 'active' }, error: null },
      groups: {
        data: [
          {
            status: 'active',
            expires_at: null,
            permission_groups: {
              key: 'disabled-vip',
              status: 'disabled',
              permission_group_permissions: [
                { permissions: { key: 'api:tier:vip' } },
              ],
            },
          },
        ],
        error: null,
      },
    })

    await expect(loadAuthorization(env, 'user-123')).resolves.toEqual({
      status: 'active',
      permissions: [],
    })
  })
})
