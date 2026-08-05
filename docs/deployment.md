# CertMate Docker 部署手册

本文覆盖 Git 构建、Docker Compose、裸 `docker run`、升级和配置生效边界。业务使用说明请回到 [README.md](../README.md)。

## 1. 部署前提

- Linux 主机、Docker Engine 和 Docker Compose v2。
- 可持久化的 `/data` 与 `/certs` 宿主机目录。
- 宿主机目录允许 UID/GID `10001:10001` 读写。
- 生产环境通过 HTTPS 反向代理访问管理页面。

```bash
mkdir -p /opt/certmate
cd /opt/certmate
git clone <repo-addr> .
mkdir -p data certs
sudo chown -R 10001:10001 data certs
```

## 2. 初始化运行配置

部署命令会自动生成并持久化 `SESSION_SECRET` 和 `APP_ENCRYPTION_KEY`。这两个值只在首次初始化时生成，后续重启或升级必须复用同一份 `.env`，不能每次重新生成，否则已有登录会话和加密 DNS 凭据会失效。

因此不要在每次 `docker run` 或 `docker compose up` 时直接写 `-e SESSION_SECRET="$(openssl rand -hex 32)"`；正确做法是先生成配置文件，再让后续部署复用该文件。

先生成管理员密码哈希；不要把明文密码写入生产配置：

```bash
htpasswd -nBC 12 admin
```

将输出中 `admin:` 后面的 bcrypt 值放入 `ADMIN_PASSWORD_HASH` 环境变量，然后执行下面的初始化命令。命令会在 `.env` 不存在时自动写入完整配置；如果 `.env` 已存在，则不会覆盖或重新生成 Secret。

```bash
export ADMIN_PASSWORD_HASH='PASTE_BCRYPT_HASH_HERE'
export DATA_HOST_DIR=/opt/certmate/data
export CERTS_HOST_DIR=/opt/certmate/certs

if [ -e .env ]; then
  echo '.env 已存在，保留现有 Secret。'
else
  test -n "$ADMIN_PASSWORD_HASH" || { echo '必须设置 ADMIN_PASSWORD_HASH' >&2; exit 1; }
  SESSION_SECRET="$(openssl rand -hex 32)"
  APP_ENCRYPTION_KEY="$(openssl rand -hex 32)"
  cat > .env <<EOF
APP_NAME=CertMate
APP_ENV=production
LISTEN_ADDR=:8080
TZ=Asia/Shanghai

ADMIN_USERNAME=admin
ADMIN_PASSWORD_HASH=${ADMIN_PASSWORD_HASH}
SESSION_SECRET=${SESSION_SECRET}
APP_ENCRYPTION_KEY=${APP_ENCRYPTION_KEY}
SESSION_COOKIE_SECURE=true

DATA_DIR=/data
CERT_OUTPUT_DIR=/certs
ACME_HOME=/data/acme
ACME_CHALLENGE_DIR=/data/challenges

DEFAULT_CA=letsencrypt
DEFAULT_ACME_EMAIL=
DEFAULT_KEY_TYPE=ec-256
ENABLE_ACME=true
ENABLE_SELF_SIGNED=true
LOG_LEVEL=info
TRUST_PROXY=false
TRUSTED_PROXY_CIDRS=
OPENSSL_BINARY=openssl
ACME_SH_BINARY=acme.sh

APP_PORT=8080
DATA_HOST_DIR=${DATA_HOST_DIR}
CERTS_HOST_DIR=${CERTS_HOST_DIR}
APP_UID=10001
APP_GID=10001
EOF
  chmod 600 .env
  mkdir -p "$DATA_HOST_DIR" "$CERTS_HOST_DIR"
  sudo chown -R 10001:10001 "$DATA_HOST_DIR" "$CERTS_HOST_DIR"
fi
```

如果采用裸 `docker run`，复用同一份已生成配置：

```bash
cp .env production.env
chmod 600 production.env
```

需要自定义 CA 或 ACME 邮箱时，在首次启动前编辑 `.env` 中的 `DEFAULT_CA`、`DEFAULT_ACME_EMAIL`；自定义 CA 必须是不含凭据和片段的 HTTPS URL。

生成后的 `.env` 至少应包含以下结构（Secret 由上面的命令自动写入）：

```env
APP_NAME=CertMate
APP_ENV=production
LISTEN_ADDR=:8080
TZ=Asia/Shanghai

ADMIN_USERNAME=admin
ADMIN_PASSWORD_HASH=<bcrypt-hash>
SESSION_SECRET=<由初始化命令自动生成>
APP_ENCRYPTION_KEY=<由初始化命令自动生成>
SESSION_COOKIE_SECURE=true

DATA_DIR=/data
CERT_OUTPUT_DIR=/certs
ACME_HOME=/data/acme
ACME_CHALLENGE_DIR=/data/challenges

DEFAULT_CA=letsencrypt
DEFAULT_ACME_EMAIL=admin@example.com
DEFAULT_KEY_TYPE=ec-256
ENABLE_ACME=true
ENABLE_SELF_SIGNED=true
LOG_LEVEL=info
TRUST_PROXY=false
TRUSTED_PROXY_CIDRS=
OPENSSL_BINARY=openssl
ACME_SH_BINARY=acme.sh

APP_PORT=8080
DATA_HOST_DIR=/opt/certmate/data
CERTS_HOST_DIR=/opt/certmate/certs
APP_UID=10001
APP_GID=10001
```

如果使用自定义 ACME Directory，可以将 `DEFAULT_CA` 设置为不含凭据和片段的 HTTPS URL。`DATA_HOST_DIR` 和 `CERTS_HOST_DIR` 是宿主机路径，必须与实际创建的目录一致；容器内路径仍固定为 `/data` 和 `/certs`。

生产环境也可以使用 `ADMIN_PASSWORD_HASH_FILE`、`SESSION_SECRET_FILE` 和 `APP_ENCRYPTION_KEY_FILE`，但必须把对应 Secret 文件以只读方式挂载到容器内，并在环境文件中填写容器内路径。不要把真实 `.env`、密码文件、Token 或私钥提交到 Git。

启动前只做静默配置校验，避免把 Secret 打印到终端：

```bash
docker compose config --quiet
```

## 3. Compose 部署（推荐）

```bash
docker compose config --quiet
docker compose build --pull
docker compose up -d
docker compose ps
curl --fail http://127.0.0.1:8080/readyz
```

Compose 默认使用 `.env`、`./data:/data`、`./certs:/certs`、非 root 用户 `10001:10001`、只读根文件系统、`/tmp` tmpfs 和 `cap_drop: ALL`。

### 使用另一套环境文件

当前 `compose.yaml` 固定写入 `env_file: .env`。因此下面的命令不会自动替换服务环境文件：

```bash
docker compose --env-file production.env up -d
```

当前版本应使用：

```bash
cp production.env .env
docker compose config --quiet
docker compose up -d --force-recreate
```

## 4. 裸 Docker Build + Docker Run

```bash
docker build --build-arg VERSION=local -t certmate:local .
docker run -d \
  --name certmate \
  --restart unless-stopped \
  --user 10001:10001 \
  --env-file ./production.env \
  -p 8080:8080 \
  -v /opt/certmate/data:/data \
  -v /opt/certmate/certs:/certs \
  --read-only \
  --tmpfs /tmp:size=64m,mode=1770,uid=10001,gid=10001 \
  --security-opt no-new-privileges:true \
  --cap-drop ALL \
  certmate:local
```

`docker run` 不会自动继承 Compose 的安全参数、挂载、端口映射和重启策略，生产部署必须显式保留这些参数。宿主机端口可以改为 `-p 18080:8080`，容器内端口仍为 `8080`。不要通过 `--build-arg` 传递运行时 Secret。

## 5. 从 Git 更新部署

更新前先备份 `/data` 和 `/certs`，并确认工作树没有本地未提交修改：

```bash
git status --short
git pull --ff-only
docker compose config --quiet
docker compose build --pull
docker compose up -d --force-recreate
docker compose ps
curl --fail http://127.0.0.1:8080/readyz
```

`build --pull` 只更新镜像，不会自动替换正在运行的旧容器；`up -d --force-recreate` 才会让新镜像和新的环境变量进入运行容器。单独执行 `docker compose restart` 通常不会重新读取新的容器环境变量。

## 6. 配置生效边界

### 6.1 需要重新创建容器的配置

端口、目录、管理员账户、Session/加密密钥、`ENABLE_ACME`、`ENABLE_SELF_SIGNED`、可信代理、日志级别以及 OpenSSL/acme.sh 路径都是启动期配置。修改后执行：

```bash
docker compose up -d --force-recreate
```

修改 `SESSION_SECRET` 会使已有登录会话失效；修改 `APP_ENCRYPTION_KEY` 可能导致已有 DNS 凭据无法解密，必须先备份 `/data`。

### 6.2 可以在管理后台动态修改的配置

- 全局续签 Cron、时区、并发数、重试次数和重试间隔；
- 单证书自动续签开关、提前续签天数和 `.renewed` 标记；
- DNS 凭据；
- 证书创建、续签和重新签发操作。

续签策略保存后会热更新调度器，不需要重启容器。

## 7. 停止、检查和恢复

```bash
docker compose ps
docker compose logs -f --tail=200 certmate
docker compose stop certmate
docker compose start certmate
```

删除容器不会删除宿主机上的 `data` 和 `certs`；删除这些目录前必须完成备份和人工确认。

## 8. 部署验收清单

- `docker compose config --quiet` 无配置错误；
- `docker compose ps` 显示服务健康；
- `/readyz` 返回成功；
- 管理页面可以登录；
- `/data` 和 `/certs` 权限属于 `10001:10001`；
- 容器没有挂载 Docker Socket；
- 生产访问经过 HTTPS 反向代理；
- 修改 `.env` 后确认执行过 `--force-recreate`；
- 已备份 SQLite、acme.sh 状态和证书目录；
- 未把真实 Secret 写入 Git、Dockerfile 或构建参数。
