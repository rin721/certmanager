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

自签名证书由本机 OpenSSL 生成，不受浏览器、Outlook、手机邮件客户端或操作系统默认信任，只适合内网、开发和测试。客户端必须自行导入信任，不能用它替代公共 CA 证书。

## 5. 三分钟快速启动

要求：Docker Engine 及 Docker Compose v2。Linux 宿主机先准备可写目录：

```bash
mkdir -p ./data ./certs
sudo chown -R 10001:10001 ./data ./certs
cp .env.example .env
```

完成下面的 Secret 配置后启动：

```bash
docker compose up -d
docker compose ps
curl http://localhost:8080/readyz
```

本机浏览器打开 `http://localhost:8080`。远程生产访问必须放在 HTTPS 反向代理后；不要把未加密的管理端口直接暴露到公网。

完整的 Compose、裸 `docker run`、Git 更新、动态配置和验收清单见 [Docker 部署手册](docs/deployment.md)。

## 6. 创建 `.env`

```bash
cp .env.example .env
```

实际 Docker 部署不要手工填写占位值；请按 [Docker 部署手册](docs/deployment.md) 中的初始化命令生成并持久化两个不同的随机值到 `SESSION_SECRET` 和 `APP_ENCRYPTION_KEY`。不要提交 `.env`。生产环境更推荐 Docker Secret/只读文件，并配置 `SESSION_SECRET_FILE`、`APP_ENCRYPTION_KEY_FILE` 与密码文件变量。

`.env.example` 已按“必填项、生成方式、容器内路径、宿主机映射和安全选项”加入中文注释；第一次部署建议先阅读注释，再复制为 `.env`。

关键目录示例：

```env
CERTS_HOST_DIR=/data/ssl
DATA_HOST_DIR=/opt/certmate/data
```

## 7. 配置管理员账户

最简单的首次启动配置：

```env
ADMIN_USERNAME=admin
ADMIN_PASSWORD=请替换为高强度长密码
```

生产环境建议使用 bcrypt 哈希，避免明文密码出现在环境变量中：

```bash
htpasswd -bnBC 12 '' '你的密码' | tr -d ':\n'
```

把结果写入 `ADMIN_PASSWORD_HASH`，并清空 `ADMIN_PASSWORD`。优先级依次为 `ADMIN_PASSWORD_HASH_FILE`、`ADMIN_PASSWORD_HASH`、`ADMIN_PASSWORD_FILE`、`ADMIN_PASSWORD`。管理员密码不会写入 SQLite。

## 8. 配置宿主机证书目录

Compose 使用：

```yaml
volumes:
  - ${DATA_HOST_DIR:-./data}:/data
  - ${CERTS_HOST_DIR:-./certs}:/certs
```

例如设置 `CERTS_HOST_DIR=/data/ssl` 后，`example.com` 的安全目录名为 `example-com`，最终文件为：

```text
/data/ssl/example-com/fullchain.pem
/data/ssl/example-com/privkey.pem
```

Web 页面只能填写 `/certs` 下的小写字母、数字、连字符子目录名，不能填写宿主机路径。容器以 UID/GID 10001 运行，挂载目录必须允许该用户读写。

## 9. 启动 Docker Compose

```bash
docker compose config --quiet
docker compose build
docker compose up -d
docker compose logs -f certmate
```

容器使用只读根文件系统、非 root 用户、`cap_drop: ALL`、`no-new-privileges` 和独立 `/tmp` tmpfs；只允许 `/data`、`/certs` 与 tmpfs 写入，未挂载 Docker Socket。

### 9.1 Git、Docker Build 与 Docker Run 部署方式

CertMate 的配置分为构建期、容器启动期和应用运行期三类。构建期只用于镜像版本和固定的 acme.sh 版本，不要把密码、Token 或加密密钥写入 Dockerfile 或 `--build-arg`。

从 Git 工作树直接构建并使用 `docker run` 时，可以把运行配置放在未提交的 `production.env` 中：

```bash
git clone <repo-addr>
cd certmanager
cp .env.example production.env
# 编辑 production.env，至少填写管理员密码/哈希、SESSION_SECRET 和 APP_ENCRYPTION_KEY

docker build \
  --build-arg VERSION=local \
  -t certmate:local .

mkdir -p ./data ./certs
docker run -d \
  --name certmate \
  --restart unless-stopped \
  --user 10001:10001 \
  --env-file ./production.env \
  -p 8080:8080 \
  -v "$(pwd)/data:/data" \
  -v "$(pwd)/certs:/certs" \
  --read-only \
  --tmpfs /tmp:size=64m,mode=1770,uid=10001,gid=10001 \
  --security-opt no-new-privileges:true \
  --cap-drop ALL \
  certmate:local
```

直接 `docker run` 不会自动继承 Compose 的安全参数、目录挂载或健康检查；生产部署应完整保留上面的 `--user`、`--read-only`、`--tmpfs`、`--cap-drop` 和两个持久化目录参数。宿主机端口可以改为 `-p 18080:8080`，容器内端口仍保持 `8080`。

使用 Compose 更新代码时，`build --pull` 只更新镜像，不会自动替换正在运行的旧容器。推荐流程是：

```bash
git pull --ff-only
docker compose config --quiet
docker compose build --pull
docker compose up -d --force-recreate
docker compose ps
curl http://localhost:8080/readyz
```

当前 `compose.yaml` 的服务配置固定引用 `.env`。`docker compose --env-file other.env` 只会改变 Compose 插值来源，不会自动替换服务的 `env_file: .env`。如需使用另一套配置，先复制为 `.env`，再执行 `docker compose up -d --force-recreate`；不要把生产 Secret 提交到 Git。

### 9.2 配置何时生效

容器启动时读取的环境变量包括端口、目录、管理员账户、Session/加密密钥、是否启用 ACME、可信代理、日志级别以及 OpenSSL/acme.sh 路径。修改这些值后必须重新创建容器；单独执行 `docker compose restart` 通常不会更新容器环境。

管理后台可以在不重启容器的情况下修改续签 Cron、时区、并发、重试策略、证书续签选项和 DNS 凭据。运行中的策略保存后会热更新调度器。

修改 `SESSION_SECRET` 会使已有登录会话失效；修改 `APP_ENCRYPTION_KEY` 可能导致已保存的 DNS 凭据无法解密，操作前必须备份 `/data`。修改 `DATA_HOST_DIR` 或 `CERTS_HOST_DIR` 时，还要同步确认宿主机目录存在且 UID/GID 10001 可读写。

## 10. 登录管理后台

从本机访问 `http://localhost:${APP_PORT:-8080}`，使用 `.env` 中的管理员账户登录。生产环境应由 HTTPS 反向代理访问并保持 `SESSION_COOKIE_SECURE=true`。

若设置 `TRUST_PROXY=true`，还必须设置明确的可信代理网段，例如同机代理：

```env
TRUST_PROXY=true
TRUSTED_PROXY_CIDRS=127.0.0.1/32,::1/128
```

不要把整个内网或 `0.0.0.0/0` 标为可信代理。

## 11. 创建第一张证书

进入“证书 → 创建证书”，选择“本地自签名证书”，填写名称、主域名、SAN、密钥类型、有效天数和安全输出目录。确认后，证书、私钥、元数据及可选 `.renewed` 标记会原子发布到宿主机目录。

创建公共证书前先在“DNS 凭据”中配置 Provider，或准备 HTTP-01 转发。普通任务不会使用 `--force`；只有管理员明确二次确认“强制续签”时才会传递该参数。

ACME CA 可以选择 Let’s Encrypt 正式环境、Staging、ZeroSSL 或填写自定义 HTTPS Directory URL。自定义地址不得包含用户名、密码或 URL 片段；正式签发前建议先在 Staging 验证域名和 DNS 配置。

创建后的证书详情页提供“重新签发”操作。它不会改变证书配置，使用现有域名、验证方式、DNS 凭据和 CA 设置重新生成并原子替换文件；签发中的、禁用的或已撤销的证书不会接受该操作。

## 12. 将证书映射给 Nginx

业务 Nginx 只需以只读方式挂载证书目录：

```yaml
services:
  nginx:
    volumes:
      - /data/ssl:/etc/nginx/certs:ro
```

```nginx
ssl_certificate     /etc/nginx/certs/example-com/fullchain.pem;
ssl_certificate_key /etc/nginx/certs/example-com/privkey.pem;
```

证书更新后由你自己的监控流程检测 `.renewed` 并执行受控的 `nginx -t && nginx -s reload`。CertMate 不获得其他容器控制权。

## 13. 将证书映射给 Stalwart

```yaml
services:
  stalwart:
    volumes:
      - /data/ssl/example-com:/opt/stalwart/certs:ro
```

在 Stalwart 配置中引用 `/opt/stalwart/certs/fullchain.pem` 和 `/opt/stalwart/certs/privkey.pem`。更新后的重载方式以你所用 Stalwart 版本的官方文档为准。

## 14. 自动续签说明

“自动续签设置”提供每天、每 12 小时、每 6 小时和五字段 Cron 模式，可设置 IANA 时区、最大并发、重试次数和间隔。保存流程先校验并启动新调度，再停止旧调度；失败时旧调度继续工作。

ACME 到期判断与协议由 acme.sh 负责；CertMate 按证书策略启动普通 `--renew`。自签名证书在进入提前天数窗口后生成新密钥和证书，验证 SAN、有效期和密钥匹配后才替换现有文件。

## 15. `.renewed` 标记文件使用方式

启用标记后，每次成功发布会写入：

```text
/data/ssl/example-com/.renewed
```

文件内容是 UTC RFC3339 时间。外部服务可轮询文件 mtime 或内容变化后自行验证配置并重载。不要让 CertMate 执行任意 Hook，也不要为此挂载 Docker Socket。

## 16. Cloudflare DNS-01 示例

在 Cloudflare 创建仅能编辑目标 Zone DNS 的 API Token。进入“DNS 凭据”，选择 Cloudflare，推荐填写 `CF_Token`；不要使用全局 API Key。凭据可加密保存到 SQLite，或只保存环境变量名引用。页面中的“测试”只做本地解密/环境变量解析，不会调用第三方 DNS API 或修改记录。随后创建公共证书，选择 DNS-01 与该凭据。

加密模式依赖 `APP_ENCRYPTION_KEY` 的 AES-GCM 保护；环境引用模式不会把值写入数据库。页面与 API 永远只返回字段名/掩码，不返回凭据值。

## 17. HTTP-01 反向代理示例

域名 A/AAAA 记录必须指向入口，公网 80 端口必须可达。Nginx 将挑战路径原样代理到 CertMate：

```nginx
location ^~ /.well-known/acme-challenge/ {
    proxy_pass http://127.0.0.1:8080;
    proxy_set_header Host $host;
}
```

其余管理界面应仅通过 HTTPS 和受限网络访问。挑战处理器只读取 `/data/challenges` 下符合安全 token 格式的普通文件，拒绝目录、符号链接和路径逃逸。DNS-01 仍是默认推荐方式。

## 18. 备份和恢复

停止写入后同时备份 `/data` 与 `/certs`：

```bash
docker compose stop certmate
sudo tar -C /opt/certmate -czf certmate-data.tgz data
sudo tar -C /data -czf certmate-certs.tgz ssl
docker compose start certmate
```

`/data` 包含 SQLite、acme.sh 账户状态、挑战目录和短期证书备份；`/certs` 包含生产证书。恢复时保持原目录所有者/权限，再启动容器。Secret 应在独立安全系统中备份，不应塞入上述归档。

## 19. 升级

```bash
docker compose stop certmate
# 先按上一节备份
git pull --ff-only
docker compose build --pull
docker compose up -d
docker compose logs --since=5m certmate
```

应用启动时自动运行向前数据库迁移，并将遗留 `running` 任务标记为 `interrupted`。不要跳过备份，也不要在多个 CertMate 实例间共享同一 SQLite 与证书目录。

## 20. 常见问题

- **容器启动失败，提示密码/Secret 缺失**：填写管理员密码、至少 32 字节的 `SESSION_SECRET`；启用 ACME 时还需至少 32 字节的 `APP_ENCRYPTION_KEY`。
- **能打开页面但登录后仍回到登录页**：生产 Secure Cookie 要求 HTTPS；本机使用 `localhost`，远程环境配置 TLS 反向代理。仅限隔离开发环境可显式设 `SESSION_COOKIE_SECURE=false`。
- **挂载目录 permission denied**：把宿主机目录所有者改为 `APP_UID`/`APP_GID`（默认 10001），或按组织策略授予等效 ACL。
- **HTTP-01 失败**：检查 DNS、80 端口、防火墙和 Nginx 挑战路径；不要把挑战请求重定向到登录页。
- **ACME 被限流**：先使用 `letsencrypt_test` Staging 验证。不要重复点击强制续签。
- **私钥下载返回 403**：先在当前会话重新输入管理员密码；重新认证有效期默认 5 分钟。

## 21. 安全说明

请阅读 [SECURITY.md](SECURITY.md)。核心措施包括 HttpOnly/Strict/Secure Cookie、CSRF、登录限流、二次认证、参数化 SQL、命令参数白名单、命令超时/输出上限、路径与符号链接检查、私钥 `0600`、常见安全头和不含敏感值的审计。

生产环境务必使用 HTTPS、限制管理端来源、保护 `.env`/Secret 文件、定期运行 `make vuln` 并及时升级。删除证书时可仅移除管理记录，或先创建 `/data/backups` 备份后删除文件。

## 22. 开发说明

要求 Go 1.25.12、Node.js 24.11.1、npm、OpenSSL；真实 ACME 由容器内固定 acme.sh 3.1.4 提供。

```bash
make frontend-dev
make backend-dev   # 另一个终端；先设置管理员和 Session 环境变量
make build
make test
make test-e2e
make lint
make verify
make vuln
make license
make docker-build
make docker-up
make docker-down
make clean
```

Windows PowerShell 可运行 `./scripts/verify.ps1`，它执行同一组格式、Go、前端构建和高等级依赖审计检查；Docker 构建仍需在安装 Docker Engine 的环境中单独执行。

主要依赖均只承担一个成熟能力：chi（HTTP 路由）、Gorilla Sessions/CSRF（Cookie 会话与 CSRF）、goose（数据库迁移）、robfig/cron（Cron 解析与调度）、modernc SQLite（无 CGO 持久化）、x/crypto（bcrypt）；前端使用 React/MUI（界面）、React Router（路由）、TanStack Query（服务端状态）、React Hook Form + Zod（表单与校验）、Vitest/Playwright（测试）。证书协议与签名分别委托给固定版本 acme.sh 和 OpenSSL，不在项目内重复实现。

普通 CI 使用 Fake ACME/Self-Signed 引擎，不请求真实 Let’s Encrypt。Playwright Smoke 使用本机 OpenSSL 创建自签名证书。真实 ACME Staging 应作为受控的手动环境测试。

## 23. 项目目录说明

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
docs/deployment.md          Docker 部署、升级与配置生效手册
.github/                    CI、Release 和 Dependabot
Dockerfile / compose.yaml   多阶段镜像与最小权限运行配置
```
