import { createClient } from '@supabase/supabase-js'
import type { AuthorizationRecord, Jwks, WorkerEnv } from './types'

interface ProfileRow {
  status: 'active' | 'disabled' | null
}

interface UserPermissionRow {
  permission_key: string
  status: 'active' | 'revoked'
  expires_at: string | null
}

export interface UserPermissionGroupRow {
  status: 'active' | 'revoked'
  expires_at: string | null
  permission_groups: {
    key: string
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
  const { data: profile } = await supabase
    .from('profiles')
    .select('status')
    .eq('id', userId)
    .maybeSingle<ProfileRow>()

  const { data: permissionRows } = await supabase
    .from('user_permissions')
    .select('permission_key,status,expires_at')
    .eq('user_id', userId)
    .returns<UserPermissionRow[]>()

  const { data: groupRows } = await supabase
    .from('user_permission_groups')
    .select(
      'status,expires_at,permission_groups(key,permission_group_permissions(permissions(key)))'
    )
    .eq('user_id', userId)
    .returns<UserPermissionGroupRow[]>()

  return {
    status: profile?.status === 'disabled' ? 'disabled' : 'active',
    permissions: buildEffectivePermissions({
      direct: permissionRows ?? [],
      groups: groupRows ?? [],
    }),
  }
}

export function buildEffectivePermissions(input: {
  direct: UserPermissionRow[]
  groups: UserPermissionGroupRow[]
}): string[] {
  const direct = activeDirectPermissions(input.direct)
  const grouped = activeGroupPermissions(input.groups)
  return [...new Set([...direct, ...grouped])].sort()
}

function activeDirectPermissions(rows: UserPermissionRow[]): string[] {
  const now = Date.now()
  return rows
    .filter((row) => row.status === 'active')
    .filter((row) => !row.expires_at || Date.parse(row.expires_at) > now)
    .map((row) => row.permission_key)
    .sort()
}

function activeGroupPermissions(rows: UserPermissionGroupRow[]): string[] {
  const now = Date.now()
  return rows
    .filter((row) => row.status === 'active')
    .filter((row) => !row.expires_at || Date.parse(row.expires_at) > now)
    .flatMap((row) =>
      row.permission_groups?.permission_group_permissions
        .map((entry) => entry.permissions?.key)
        .filter((key): key is string => typeof key === 'string') ?? []
    )
}
