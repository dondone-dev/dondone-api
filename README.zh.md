# Dondone API

[English](./README.md)

基于 Cloudflare Workers + Hono 的 Dondone API 服务，用于验证 Dondone API JWT、查询 Supabase 授权数据，并返回用户权限与 `normal`/`vip` 分层。

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

在 Cloudflare Workers 中配置：

```sh
AUTH_ISSUER=https://auth.dondone.dev
AUTH_AUDIENCE=https://api.dondone.dev
AUTH_JWKS_URL=https://auth.dondone.dev/api/jwks
SUPABASE_URL=<supabase-project-url>
SUPABASE_SERVICE_ROLE_KEY=<secret>
RESOURCE_ACCESS_TOKENS_ENABLED=false
```

`SUPABASE_SERVICE_ROLE_KEY` 必须作为 secret 配置，不能提交到仓库。

`RESOURCE_ACCESS_TOKENS_ENABLED` 是发布开关，已在 `wrangler.toml` 中显式设为 `"false"`。资源模式（`"true"`）下，`/echo` 只接受 ES256 `at+jwt`：header 必须有非空且匹配的 `kid`，`aud` 必须是单一字符串并精确等于 `AUTH_AUDIENCE`，scope 必须包含 `api:echo`，且 token 中每个 scope 都必须在当前 well-known manifest 的 `scopes_supported` 中。scope 只是请求能力上限；服务每次请求仍会读取 Supabase 当前 grant，撤销后立即拒绝。

开关为 `"false"` 时处于双读迁移期，仍接受旧 `typ=JWT` token。每个成功授权的旧 token 请求会输出一条结构化 JSON 日志：`event=legacy_access_token_accepted`，并包含 resource 与 user ID。应在 Worker 日志中统计该事件：先在 `dondone-auth` 开启资源 token 签发并迁移客户端；连续一个 token 最大有效期再加部署缓冲时间都为零后，才开启 API 的资源模式。

公开的 `GET /.well-known/oauth-protected-resource` 是随服务版本发布的 RFC 9728 元数据。`scopes_supported` 只列 OAuth scope；`dondone_capabilities.permissions` 还可声明 `api:tier:vip` 这类实时策略权限，它不会写入 token scope。

从 Supabase Dashboard 获取 service role key：

1. 打开你的 Supabase project。
2. 进入 **Project Settings** → **API Keys**。
3. 在 API keys 列表中，复制具备 service role 权限的 secret key，通常以 `sb_secret_...` 开头。

Supabase 默认可能会显示一个 `default` API key。不要把 publishable/default client key 用在这里；`dondone-api` 需要 service role secret key，因为它要在服务端读取授权表。

使用 Wrangler 写入 service role key，然后粘贴从 Supabase 复制的值：

```sh
pnpm wrangler secret put SUPABASE_SERVICE_ROLE_KEY
```

也可以通过管道写入，例如：

```sh
echo "sb_secret_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" | pnpm wrangler secret put SUPABASE_SERVICE_ROLE_KEY
```

## 开发

```sh
pnpm install
pnpm test
pnpm build
pnpm dev
```
