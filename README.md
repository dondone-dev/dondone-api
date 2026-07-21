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

Runtime configuration is declared as public vars in `wrangler.toml`:

```sh
AUTH_ISSUER=https://auth.dondone.dev
AUTH_AUDIENCE=https://api.dondone.dev
AUTH_JWKS_URL=https://auth.dondone.dev/api/jwks
AUTH_USAGE_URL=https://auth.dondone.dev
```

This service does not access Supabase directly and requires no Supabase secret. Authorization — the permission grant plus usage-policy check — is delegated per request to the Dondone Auth usage endpoint at `AUTH_USAGE_URL`.

`/echo` accepts only ES256 `at+jwt` tokens with a non-empty matching `kid`, a single `aud` exactly equal to `AUTH_AUDIENCE`, and the `api:echo` scope. Every token scope must be listed by this release's well-known manifest. The scope is only an upper bound: `/echo` also re-checks the current permission grant on every request via the usage service. Legacy `typ=JWT` tokens are rejected.

The public `GET /.well-known/oauth-protected-resource` endpoint is the release-owned RFC 9728 metadata document. `scopes_supported` contains OAuth request scopes; `dondone_capabilities.permissions` may additionally contain live policy permissions such as `api:tier:vip` that are deliberately not token scopes.

## Development

```sh
pnpm install
pnpm test
pnpm build
pnpm dev
```
