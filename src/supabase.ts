import { createClient } from '@supabase/supabase-js'
import type { AuthorizationRecord, Jwks, WorkerEnv } from './types'

interface ProfileRow {
  status: 'active' | 'disabled' | null
}

export interface UserPermissionGroupRow {
  status: 'active' | 'revoked'
  expires_at: string | null
  permission_groups: {
    key: string
    status: 'active' | 'disabled'
    permission_group_permissions: Array<{
      permissions: {
        key: string
      } | null
    }>
  } | null
}

export async function fetchJwks(env: WorkerEnv): Promise<Jwks> {
  const response = await fetch(env.AUTH_JWKS_URL)
  if (!response.ok) {
    throw new Error('Failed to fetch JWKS.')
  }
  return (await response.json()) as Jwks
}

export async function loadAuthorization(
  env: WorkerEnv,
  userId: string
): Promise<AuthorizationRecord> {
  const supabase = createClient(env.SUPABASE_URL, env.SUPABASE_SERVICE_ROLE_KEY, {
    auth: { persistSession: false },
  })
  const { data: profile, error: profileError } = await supabase
    .from('profiles')
    .select('status')
    .eq('id', userId)
    .maybeSingle<ProfileRow>()

  if (profileError) throw new Error(`Profile query failed: ${profileError.message}`)
  if (!profile) return { status: 'disabled', permissions: [] }

  const { data: groupRows, error: groupError } = await supabase
    .from('user_permission_groups')
    .select(
      'status,expires_at,permission_groups(key,status,permission_group_permissions(permissions(key)))'
    )
    .eq('user_id', userId)
    .returns<UserPermissionGroupRow[]>()

  if (groupError) throw new Error(`Permission group query failed: ${groupError.message}`)

  return {
    status: profile.status === 'disabled' ? 'disabled' : 'active',
    permissions: buildEffectivePermissions({
      groups: groupRows ?? [],
    }),
  }
}

export function buildEffectivePermissions(input: {
  groups: UserPermissionGroupRow[]
}): string[] {
  const grouped = activeGroupPermissions(input.groups)
  return [...new Set(grouped)].sort()
}

function activeGroupPermissions(rows: UserPermissionGroupRow[]): string[] {
  const now = Date.now()
  return rows
    .filter((row) => row.status === 'active')
    .filter((row) => !row.expires_at || Date.parse(row.expires_at) > now)
    .filter((row) => row.permission_groups?.status === 'active')
    .flatMap((row) =>
      row.permission_groups?.permission_group_permissions
        .map((entry) => entry.permissions?.key)
        .filter((key): key is string => typeof key === 'string') ?? []
    )
}
