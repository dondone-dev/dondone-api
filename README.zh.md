# Dondone API

[English](./README.md)

基于 Cloudflare Workers + Hono 的 Dondone API 服务，用于验证 Dondone API JWT，并将授权（权限 grant 与用量策略）委托给 Dondone Auth 的 usage 端点校验。

## API

| 端点 | 说明 |
|---|---|
| `GET /health` | 返回服务健康状态。 |
| `GET /echo` | 验证 Dondone access token，并返回用户 tier 与 permissions。 |
| `GET /.well-known/oauth-protected-resource` | 发布 RFC 9728 资源元数据、OAuth scopes 与服务能力目录，缓存 5 分钟。 |

`/echo` 需要：

```http
Authorization: Bearer <Dondone access token>
```

## 环境变量

运行时配置以公开 vars 声明在 `wrangler.toml` 中：

```sh
AUTH_ISSUER=https://auth.dondone.dev
AUTH_AUDIENCE=https://api.dondone.dev
AUTH_JWKS_URL=https://auth.dondone.dev/api/jwks
AUTH_USAGE_URL=https://auth.dondone.dev
```

本服务不直接访问 Supabase，也不需要任何 Supabase secret。授权（权限 grant 与用量策略）在每次请求时委托给 `AUTH_USAGE_URL` 指向的 Dondone Auth usage 端点校验。

`/echo` 只接受 ES256 `at+jwt`：header 必须有非空且匹配的 `kid`，`aud` 必须是单一字符串并精确等于 `AUTH_AUDIENCE`，scope 必须包含 `api:echo`，且 token 中每个 scope 都必须在当前 well-known manifest 的 `scopes_supported` 中。scope 只是请求能力上限；服务每次请求仍会通过 usage 端点复检当前权限 grant，撤销后立即拒绝。旧 `typ=JWT` token 会被拒绝。

公开的 `GET /.well-known/oauth-protected-resource` 是随服务版本发布的 RFC 9728 元数据。`scopes_supported` 只列 OAuth scope；`dondone_capabilities.permissions` 还可声明 `api:tier:vip` 这类实时策略权限，它不会写入 token scope。

## 开发

```sh
pnpm install
pnpm test
pnpm build
pnpm dev
```
