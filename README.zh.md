# Dondone API

[English](./README.md)

基于 Cloudflare Workers + Hono 的 Dondone API 服务，用于验证 Dondone API JWT、查询 Supabase 授权数据，并返回用户权限与 `normal`/`vip` 分层。

## API

| 端点 | 说明 |
|---|---|
| `GET /health` | 返回服务健康状态。 |
| `GET /echo` | 验证 Dondone API JWT，并返回用户 tier 与 permissions。 |

`/echo` 需要：

```http
Authorization: Bearer <Dondone API JWT>
```

## 环境变量

在 Cloudflare Workers 中配置：

```sh
AUTH_ISSUER=https://auth.dondone.dev
AUTH_AUDIENCE=https://api.dondone.dev
AUTH_JWKS_URL=https://auth.dondone.dev/api/jwks
SUPABASE_URL=<supabase-project-url>
SUPABASE_SERVICE_ROLE_KEY=<secret>
```

`SUPABASE_SERVICE_ROLE_KEY` 必须作为 secret 配置，不能提交到仓库。

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
