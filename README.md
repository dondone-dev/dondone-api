# Dondone API

[中文文档](./README.zh.md)

Cloudflare Workers + Hono API service for Dondone authorization checks.

## API

| Endpoint | Description |
|---|---|
| `GET /health` | Returns service health. |
| `GET /echo` | Verifies a Dondone access token and returns the user tier and permissions. |
| `GET /.well-known/oauth-protected-resource` | RFC 9728 Protected Resource Metadata — declares this service's capabilities, scopes, and authorization server. Cached for 5 minutes. |

`/echo` requires:

```http
Authorization: Bearer <Dondone access token>
```

## Environment

Configure these in Cloudflare Workers:

```sh
AUTH_ISSUER=https://auth.dondone.dev
AUTH_AUDIENCE=https://api.dondone.dev
AUTH_JWKS_URL=https://auth.dondone.dev/api/jwks
SUPABASE_URL=<supabase-project-url>
SUPABASE_SERVICE_ROLE_KEY=<secret>
RESOURCE_ACCESS_TOKENS_ENABLED=false
```

`SUPABASE_SERVICE_ROLE_KEY` must be configured as a secret, not committed.

`RESOURCE_ACCESS_TOKENS_ENABLED` is a rollout feature flag and is explicitly `"false"` in `wrangler.toml`. In resource mode (`"true"`), `/echo` accepts only ES256 `at+jwt` tokens with a non-empty matching `kid`, a single `aud` exactly equal to `AUTH_AUDIENCE`, and the `api:echo` scope. Every token scope must be listed by this release's well-known manifest. The scope is only an upper bound: `/echo` also requires the current Supabase grant on every request.

When the flag is `"false"`, legacy `typ=JWT` tokens remain accepted during migration. Every successfully authorized legacy request emits one structured JSON log with `event=legacy_access_token_accepted`, the resource, and the user ID. Track that event in Worker logs or a log-based metric. Enable resource-token issuance in `dondone-auth`, migrate clients, and wait until the event count remains zero for at least the maximum token lifetime plus deployment buffer before enabling this API flag. Do not enable the API flag before callers send audience-bound `at+jwt` tokens.

The public `GET /.well-known/oauth-protected-resource` endpoint is the release-owned RFC 9728 metadata document. `scopes_supported` contains OAuth request scopes; `dondone_capabilities.permissions` may additionally contain live policy permissions such as `api:tier:vip` that are deliberately not token scopes.

Get the service role key from Supabase Dashboard:

1. Open your Supabase project.
2. Go to **Project Settings** → **API Keys**.
3. In the API keys list, copy the key that has service role privileges. It usually starts with `sb_secret_...`.

Supabase may show a `default` API key by default. Do not use the publishable/default client key for this service; `dondone-api` needs the service role secret key because it reads authorization tables on the server side.

Set the service role key with Wrangler, then paste the value from Supabase:

```sh
pnpm wrangler secret put SUPABASE_SERVICE_ROLE_KEY
```

The value should be the Supabase service role secret key, for example:

```sh
echo "sb_secret_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" | pnpm wrangler secret put SUPABASE_SERVICE_ROLE_KEY
```

## Development

```sh
pnpm install
pnpm test
pnpm build
pnpm dev
```
