# Dondone API

[中文文档](./README.zh.md)

Cloudflare Workers + Hono API service for Dondone authorization checks.

## API

| Endpoint | Description |
|---|---|
| `GET /health` | Returns service health. |
| `GET /echo` | Verifies a Dondone API JWT and returns the user tier and permissions. |

`/echo` requires:

```http
Authorization: Bearer <Dondone API JWT>
```

## Environment

Configure these in Cloudflare Workers:

```sh
AUTH_ISSUER=https://auth.dondone.dev
AUTH_AUDIENCE=https://api.dondone.dev
AUTH_JWKS_URL=https://auth.dondone.dev/api/jwks
SUPABASE_URL=<supabase-project-url>
SUPABASE_SERVICE_ROLE_KEY=<secret>
```

`SUPABASE_SERVICE_ROLE_KEY` must be configured as a secret, not committed.

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
