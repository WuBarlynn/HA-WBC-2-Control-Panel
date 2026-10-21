# API Token 使用说明

> 应用层长期凭据，供助手（如 Grok Bot）调用控制台 HTTP API。  
> 实现依据：`docs/认证扩展分析.md` 方案 A。  
> **禁止把真实 Token 写进 git、群聊或文档。**

## 行为摘要

| 项 | 说明 |
|----|------|
| 格式 | `wbc_` + 64 位 hex（32 字节随机） |
| 存储 | 仅 SHA-256 哈希写入 `ha-wbc-data.json` 的 `apiTokens`；明文只在创建响应出现一次 |
| 传递 | `Authorization: Bearer <token>` |
| 默认 scope | `read` + `power` |
| 管理 | 仅人类会话（密码 / Passkey 登录后）可创建、列表、吊销；**API Token 不能管 Token** |
| 与会话区别 | 会话在内存、重启失效；API Token 持久化、重启仍有效 |

### Scope

| Scope | 可调用 |
|-------|--------|
| `read` | `GET /api/devices`、`/api/overview`、设备 status/info/device-state/wifi-list/check-update/update-progress |
| `power` | `POST .../power`、`restart`、`autostart`、`childlock`、`force-shutdown` |

人类会话：上述全部 + 设备 CRUD、配网、固件、出厂、改密、Passkey、HomeKit、Token 管理。

## 设置页操作

1. 密码或通行密钥登录控制台。  
2. 打开 **系统设置** → **API Token（助手 / 自动化）**。  
3. 填写名称（如 `grok-bot`），勾选 `read` / `power`，点 **创建 API Token**。  
4. 弹出的明文 **立即复制**到助手密钥库；关闭后无法再查看。  
5. 列表可按前缀识别；点垃圾桶 **吊销**（立即生效）。

## curl 示例（占位符）

总览：

```bash
curl -sS 'https://wbc.wubarlynn.top/api/overview' \
  -H 'Authorization: Bearer wbc_REPLACE_WITH_API_TOKEN'
```

开机（`DEVICE_ID` 来自 devices/overview；`state: true` 开 / `false` 关）：

```bash
curl -sS -X POST 'https://wbc.wubarlynn.top/api/devices/DEVICE_ID/power' \
  -H 'Authorization: Bearer wbc_REPLACE_WITH_API_TOKEN' \
  -H 'Content-Type: application/json' \
  -d '{"state":true}'
```

管理接口（需人类会话，勿用 API Token）：

```bash
# 列表（无明文）
curl -sS 'https://wbc.wubarlynn.top/api/tokens' \
  -H 'Authorization: Bearer SESSION_TOKEN'

# 创建
curl -sS -X POST 'https://wbc.wubarlynn.top/api/tokens' \
  -H 'Authorization: Bearer SESSION_TOKEN' \
  -H 'Content-Type: application/json' \
  -d '{"name":"grok-bot","scopes":["read","power"]}'

# 吊销
curl -sS -X DELETE 'https://wbc.wubarlynn.top/api/tokens/TOKEN_ID' \
  -H 'Authorization: Bearer SESSION_TOKEN'
```

## 部署注意（现网 OpenWrt）

1. 在本机 `~/dev/HA-WBC-2-Control-Panel` 用 `./build.sh`（或交叉编译）产出目标平台二进制。  
2. 停掉 OpenWrt 上旧进程，替换二进制；**保留**现有 `ha-wbc-data.json`（管理员密码、设备、Passkey 不变；新字段 `apiTokens` 会自动出现）。  
3. Cloudflare Tunnel / DNS **无需改动**。  
4. 浏览器登录 → 设置页创建 Token → 把明文交给助手配置；用上面 curl 自测 `overview` / `power`。  
5. 轮换：设置页吊销旧 Token → 新建 → 更新助手侧凭据。

## 本地验证

```bash
cd ~/dev/HA-WBC-2-Control-Panel
GOPROXY=https://goproxy.cn,direct go test ./internal/server/ -count=1
GOPROXY=https://goproxy.cn,direct go build -o /tmp/ha-wbc-console .
```
