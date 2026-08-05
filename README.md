# CertMate

## 1. 这个项目是什么

CertMate 是一个面向 Linux + Docker 的轻量级 SSL/TLS 证书自助管理后台。它以单个 Go 进程提供 REST API、React 管理界面、动态续签调度和静态文件服务，元数据存入 SQLite，证书文件直接发布到宿主机映射目录。

## 2. 能做什么

- 使用 acme.sh 签发、续签和撤销公共 CA 证书，支持 DNS-01 与 HTTP-01。
- 使用 OpenSSL 生成和定期重新生成本地自签名证书。
- 管理 Cloudflare、阿里云、DNSPod、AWS Route 53、华为云和自定义 acme.sh DNS Provider 凭据。
- 查看、复制、单文件下载证书；私钥查看、复制和下载需重新认证并写审计记录。
- 在线修改 Cron、时区、并发和重试策略，保存后无需重启。
- 查看任务日志、审计记录和不含 Secret 的系统信息。

## 3. 不能做什么

CertMate 不是企业 PKI、密钥托管服务或多租户证书平台。第一版没有 RBAC、OAuth、多节点调度、Kubernetes 控制器、Docker Socket 集成、任意脚本 Hook，也不会替你修改 Nginx、Stalwart 或 DNS 服务配置。

## 4. ACME 证书与自签名证书的区别

公共 CA 证书由 Let’s Encrypt 等受信任 CA 签发，适合互联网网站、邮件和其他需要系统默认信任的服务；签发时必须证明域名控制权。CertMate 将协议处理交给固定版本的 acme.sh。

自签名证书由容器内 OpenSSL 生成，不受浏览器、Outlook、手机邮件客户端或操作系统默认信任，只适合内网、开发和测试。客户端必须自行导入信任，不能用它替代公共 CA 证书。

## 5. Docker Compose 部署

Linux 主机只需安装 Git、Bash、Docker Engine 和 Docker Compose v2，然后使用两阶段部署脚本：

```bash
git clone <repo-addr> certmate
cd certmate

# 第一次只创建 .env 并停止。
bash scripts/deploy.sh init

# 输入管理员密码两次；脚本只保存 bcrypt 哈希。
bash scripts/deploy.sh configure-admin

# 编辑 .env：确认宿主机数据目录、证书目录和端口。
nano .env

# 第二次自动生成 Session/加密 Secret，构建并启动 Compose。
bash scripts/deploy.sh init
```

后续升级使用：

```bash
bash scripts/deploy.sh update
```

脚本不会覆盖已有 Secret，不会自动提权；目录权限不足时会打印需要人工确认的 `sudo` 命令。`.env` 的完整中文注释、bcrypt 写法、目录映射、裸 `docker run`、备份和故障处理见 [Docker 部署手册](docs/deployment.md)。

本机浏览器默认打开 `http://localhost:8080`。远程生产访问必须放在 HTTPS 反向代理后，不要直接暴露未加密的管理端口。

## 6. 登录管理后台

从本机访问 `http://localhost:${APP_PORT:-8080}`，使用 `.env` 中的管理员账户登录。生产环境应由 HTTPS 反向代理访问并保持 `SESSION_COOKIE_SECURE=true`。

若设置 `TRUST_PROXY=true`，还必须设置明确的可信代理网段，例如同机代理：

```env
TRUST_PROXY=true
TRUSTED_PROXY_CIDRS=127.0.0.1/32,::1/128
```

不要把整个内网或 `0.0.0.0/0` 标为可信代理。

## 7. 创建第一张证书

进入“证书 → 创建证书”，选择“本地自签名证书”，填写名称、主域名、SAN、密钥类型、有效天数和安全输出目录。确认后，证书、私钥、元数据及可选 `.renewed` 标记会原子发布到宿主机目录。

创建公共证书前先在“DNS 凭据”中配置 Provider，或准备 HTTP-01 转发。普通任务不会使用 `--force`；只有管理员明确二次确认“强制续签”时才会传递该参数。

ACME CA 可以选择 Let’s Encrypt 正式环境、Staging、ZeroSSL 或填写自定义 HTTPS Directory URL。自定义地址不得包含用户名、密码或 URL 片段；正式签发前建议先在 Staging 验证域名和 DNS 配置。

创建后的证书详情页提供“重新签发”操作。它不会改变证书配置，使用现有域名、验证方式、DNS 凭据和 CA 设置重新生成并原子替换文件；签发中的、禁用的或已撤销的证书不会接受该操作。

## 8. 将证书映射给 Nginx

业务 Nginx 只需以只读方式挂载证书目录：

```yaml
services:
  nginx:
    volumes:
      - ./certs:/etc/nginx/certs:ro
```

```nginx
ssl_certificate     /etc/nginx/certs/example-com/fullchain.pem;
ssl_certificate_key /etc/nginx/certs/example-com/privkey.pem;
```

证书更新后由你自己的监控流程检测 `.renewed` 并执行受控的 `nginx -t && nginx -s reload`。CertMate 不获得其他容器控制权。

## 9. 将证书映射给 Stalwart

```yaml
services:
  stalwart:
    volumes:
      - ./certs/example-com:/opt/stalwart/certs:ro
```

在 Stalwart 配置中引用 `/opt/stalwart/certs/fullchain.pem` 和 `/opt/stalwart/certs/privkey.pem`。更新后的重载方式以你所用 Stalwart 版本的官方文档为准。

## 10. 自动续签说明

“自动续签设置”提供每天、每 12 小时、每 6 小时和五字段 Cron 模式，可设置 IANA 时区、最大并发、重试次数和间隔。保存流程先校验并启动新调度，再停止旧调度；失败时旧调度继续工作。

ACME 到期判断与协议由 acme.sh 负责；CertMate 按证书策略启动普通 `--renew`。自签名证书在进入提前天数窗口后生成新密钥和证书，验证 SAN、有效期和密钥匹配后才替换现有文件。

## 11. `.renewed` 标记文件使用方式

启用标记后，每次成功发布会写入：

```text
./certs/example-com/.renewed
```

文件内容是 UTC RFC3339 时间。外部服务可轮询文件 mtime 或内容变化后自行验证配置并重载。不要让 CertMate 执行任意 Hook，也不要为此挂载 Docker Socket。

## 12. Cloudflare DNS-01 示例

在 Cloudflare 创建仅能编辑目标 Zone DNS 的 API Token。进入“DNS 凭据”，选择 Cloudflare，推荐填写 `CF_Token`；不要使用全局 API Key。凭据可加密保存到 SQLite，或只保存环境变量名引用。页面中的“测试”只做本地解密/环境变量解析，不会调用第三方 DNS API 或修改记录。随后创建公共证书，选择 DNS-01 与该凭据。

加密模式依赖 `APP_ENCRYPTION_KEY` 的 AES-GCM 保护；环境引用模式不会把值写入数据库。页面与 API 永远只返回字段名/掩码，不返回凭据值。

## 13. HTTP-01 反向代理示例

域名 A/AAAA 记录必须指向入口，公网 80 端口必须可达。Nginx 将挑战路径原样代理到 CertMate：

```nginx
location ^~ /.well-known/acme-challenge/ {
    proxy_pass http://127.0.0.1:8080;
    proxy_set_header Host $host;
}
```

其余管理界面应仅通过 HTTPS 和受限网络访问。挑战处理器只读取 `/data/challenges` 下符合安全 token 格式的普通文件，拒绝目录、符号链接和路径逃逸。DNS-01 仍是默认推荐方式。

## 14. 备份和恢复

停止写入后同时备份 `.env`、`DATA_HOST_DIR` 与 `CERTS_HOST_DIR` 指向的实际宿主机目录。数据目录包含 SQLite、acme.sh 账户状态、挑战目录和短期证书备份；证书目录包含生产证书。恢复时保持原目录所有者和权限。备份范围和操作注意事项见 [Docker 部署手册](docs/deployment.md)。

## 15. 升级

```bash
# 先按上一节备份
bash scripts/deploy.sh update
```

脚本只接受 fast-forward Git 更新，并拒绝覆盖 tracked 文件修改。应用启动时自动运行向前数据库迁移，并将遗留 `running` 任务标记为 `interrupted`。不要跳过备份，也不要在多个 CertMate 实例间共享同一 SQLite 与证书目录。

## 16. 常见问题

- **第一次运行没有启动 Docker**：这是正常的配置阶段；编辑新生成的 `.env` 后再次运行 `bash scripts/deploy.sh init`。
- **容器启动失败，提示密码/Secret 缺失**：确认管理员密码来源；两个内联 Secret 默认由部署脚本自动生成。
- **能打开页面但登录后仍回到登录页**：生产 Secure Cookie 要求 HTTPS；本机使用 `localhost`，远程环境配置 TLS 反向代理。仅限隔离开发环境可显式设 `SESSION_COOKIE_SECURE=false`。
- **挂载目录 permission denied**：把宿主机目录所有者改为 `APP_UID`/`APP_GID`（默认 10001），或按组织策略授予等效 ACL。
- **HTTP-01 失败**：检查 DNS、80 端口、防火墙和 Nginx 挑战路径；不要把挑战请求重定向到登录页。
- **ACME 被限流**：先使用 `letsencrypt_test` Staging 验证。不要重复点击强制续签。
- **私钥下载返回 403**：先在当前会话重新输入管理员密码；重新认证有效期默认 5 分钟。

## 17. 安全说明

请阅读 [SECURITY.md](SECURITY.md)。核心措施包括 HttpOnly/Strict/Secure Cookie、CSRF、登录限流、二次认证、参数化 SQL、命令参数白名单、命令超时/输出上限、路径与符号链接检查、私钥 `0600`、常见安全头和不含敏感值的审计。

生产环境务必使用 HTTPS、限制管理端来源、保护 `.env`/Secret 文件、定期运行 `make vuln` 并及时升级。删除证书时可仅移除管理记录，或先创建 `/data/backups` 备份后删除文件。

## 18. 开发说明

要求 Go 1.25.12、Node.js 24.11.1、npm、OpenSSL；真实 ACME 由容器内固定 acme.sh 3.1.4 提供。

```bash
make frontend-dev
make backend-dev   # 另一个终端；先设置管理员和 Session 环境变量
make build
make test
make test-e2e
make lint
make deploy-test
make verify
make vuln
make license
make docker-build
make docker-up
make docker-down
make clean
```

Windows PowerShell 可运行 `./scripts/verify.ps1` 检查 Go、前端构建和高等级依赖审计；Linux 部署脚本使用 `make deploy-test` 验证。Docker 构建仍需在安装 Docker Engine 的环境中单独执行。

主要依赖均只承担一个成熟能力：chi（HTTP 路由）、Gorilla Sessions/CSRF（Cookie 会话与 CSRF）、goose（数据库迁移）、robfig/cron（Cron 解析与调度）、modernc SQLite（无 CGO 持久化）、x/crypto（bcrypt）；前端使用 React/MUI（界面）、React Router（路由）、TanStack Query（服务端状态）、React Hook Form + Zod（表单与校验）、Vitest/Playwright（测试）。证书协议与签名分别委托给固定版本 acme.sh 和 OpenSSL，不在项目内重复实现。

普通 CI 使用 Fake ACME/Self-Signed 引擎，不请求真实 Let’s Encrypt。Playwright Smoke 使用本机 OpenSSL 创建自签名证书。真实 ACME Staging 应作为受控的手动环境测试。

## 19. 项目目录说明

```text
cmd/server/                 进程入口与健康检查命令
internal/app/               生命周期与组合根
internal/auth/              单管理员 Session、重新认证、限流
internal/certificate/       证书服务、acme.sh/OpenSSL 适配、解析与安全发布
internal/credential/        DNS Provider 注册表、加密和环境引用
internal/httpapi/           REST 路由、中间件与协议转换
internal/scheduler/         动态 Cron 和非重入扫描
internal/store/sqlite/      SQLite 持久化与迁移执行
internal/systeminfo/        限时、限输出的运行信息采集
migrations/                 goose 嵌入式 SQL 迁移
web/                        React、MUI、TanStack Query、Vitest、Playwright
deploy/                     反向代理示例
scripts/                    Linux 部署脚本、隔离测试与 PowerShell 验证入口
docs/deployment.md          Docker 部署、升级与配置生效手册
.github/                    CI、Release 和 Dependabot
Dockerfile / compose.yaml   多阶段镜像与最小权限运行配置
```
