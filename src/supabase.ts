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

  return {
    status: profile?.status === 'disabled' ? 'disabled' : 'active',
    permissions: activePermissions(permissionRows ?? []),
  }
}

function activePermissions(rows: UserPermissionRow[]): string[] {
  const now = Date.now()
  return rows
    .filter((row) => row.status === 'active')
    .filter((row) => !row.expires_at || Date.parse(row.expires_at) > now)
    .map((row) => row.permission_key)
    .sort()
}
