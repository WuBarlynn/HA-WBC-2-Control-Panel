# 现网部署：API Token 版（OpenWrt）

> 部署由用户自行完成。本文档不含真实密钥；助手不得 SSH 改现网。

## 目标架构

| 项 | 值 | 依据 |
| --- | --- | --- |
| GOOS/GOARCH | `linux` / `arm64` | Cloudflare Tunnel 名 `ax3000t`（Xiaomi AX3000T / Filogic → aarch64）；`build.sh` 含 `linux arm64` |
| 产物名 | `ha-wbc-console_<VERSION>_linux_arm64` | 与 README / `build.sh` 一致 |
| 公网 | `https://wbc.wubarlynn.top` → Tunnel → `localhost:8088` | **Tunnel / DNS 无需改动** |

本机交叉编译（在 Mac 上）：

```bash
cd ~/dev/HA-WBC-2-Control-Panel
VERSION=1.3.8 ./build.sh
# 或仅 OpenWrt：
# CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath \
#   -ldflags "-s -w -X main.version=1.3.8" \
#   -o dist/ha-wbc-console_1.3.8_linux_arm64 .
```

校验示例（以本机构建产物为准，sha256 以实际文件为准）：

```bash
ls -lh dist/ha-wbc-console_1.3.8_linux_arm64
file dist/ha-wbc-console_1.3.8_linux_arm64
shasum -a 256 dist/ha-wbc-console_1.3.8_linux_arm64
```

也可从 GitHub Release 下载同名二进制。

## 部署步骤（用户操作）

1. **备份**：旧二进制 + 同目录 `ha-wbc-data.json`（及证书若有）。
2. **停服务**：按现网方式停控制台进程（procd / init / 手工 `kill` 等）。
3. **换二进制**：上传新 `ha-wbc-console_*_linux_arm64`，替换可执行文件并 `chmod +x`。
4. **保留 data JSON**：不要覆盖或删除 `ha-wbc-data.json`（密码、设备、Passkey 保留；新字段 `apiTokens` 会自动出现）。
5. **重启**控制台进程。
6. **Cloudflare Tunnel**：无需修改。
7. 浏览器登录 → **系统设置 → API Token** → 创建（明文只一次）→ 交给助手密钥库。
8. curl 自测（占位符）：

```bash
curl -sS 'https://wbc.wubarlynn.top/api/overview' \
  -H 'Authorization: Bearer wbc_REPLACE_WITH_API_TOKEN'

curl -sS -X POST 'https://wbc.wubarlynn.top/api/devices/DEVICE_ID/power' \
  -H 'Authorization: Bearer wbc_REPLACE_WITH_API_TOKEN' \
  -H 'Content-Type: application/json' \
  -d '{"state":true}'
```

详见 [`API-Token.md`](./API-Token.md)。
