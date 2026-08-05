# CertMate Docker 部署手册

本文是 CertMate Docker 部署与升级的权威说明。推荐方式是 Linux 主机上的两阶段部署脚本加 Docker Compose；业务使用说明请回到 [README.md](../README.md)。

## 1. 部署前提

部署主机需要：

- Linux；
- Git；
- Bash；
- Docker Engine；
- Docker Compose v2，即 `docker compose` 命令。

CertMate 只运行一个常驻应用容器，不使用 Docker Socket。bcrypt、随机 Secret 和证书所需工具都在项目自己的 Docker 镜像中，宿主机不需要安装 Apache、`htpasswd`、OpenSSL、Go 或 Node.js。SQLite、acme.sh 状态和证书分别持久化到宿主机目录。

## 2. 首次部署

### 2.1 Clone 仓库

```bash
git clone <repo-addr> certmate
cd certmate
```

部署脚本位于仓库内，因此首次 clone 仍由用户执行，不使用不透明的远程 `curl | sh` 安装方式。

### 2.2 第一次运行：只创建 `.env`

```bash
bash scripts/deploy.sh init
```

当 `.env` 不存在时，脚本只执行以下操作：

1. 复制 `.env.example` 为 `.env`；
2. 将 `.env` 权限设为 `0600`；
3. 显示必须配置的字段；
4. 以成功状态停止，不生成 Secret，也不调用 Docker。

先通过脚本配置管理员账户。脚本会询问用户名，并隐藏输入、确认两次密码；密码不会进入 Shell 历史：

```bash
bash scripts/deploy.sh configure-admin
```

脚本会构建项目内的最小一次性 helper 镜像，通过 stdin 将密码交给无网络、只读、无 Linux capabilities 的临时容器生成 bcrypt。最终只把单引号保护的哈希写入 `ADMIN_PASSWORD_HASH`，并清空其他管理员密码来源；明文密码不会写入 `.env`、命令行或日志。

然后编辑其余配置：

```bash
nano .env
```

至少确认以下内容：

```env
# 默认映射到项目根目录下的相对目录。
DATA_HOST_DIR=./data
CERTS_HOST_DIR=./certs

# 容器使用的宿主机 UID/GID，默认保持 10001。
APP_UID=10001
APP_GID=10001

# 这两个值保持为空，第二次运行由脚本自动生成。
SESSION_SECRET=
APP_ENCRYPTION_KEY=
```

`DATA_HOST_DIR` 保存 SQLite、acme.sh 状态、任务临时文件和备份；`CERTS_HOST_DIR` 保存对外使用的证书文件。它们必须是彼此独立的目录。

### 2.3 管理员账户与密码轮换

如果没有单独运行 `configure-admin`，第二次在交互终端运行 `init` 时也会检测到管理员密码缺失，并进入相同的用户名和密码配置流程。

以后轮换管理员用户名或密码仍使用：

```bash
bash scripts/deploy.sh configure-admin
bash scripts/deploy.sh init
```

生成后的配置形式为：

```env
ADMIN_PASSWORD_HASH='$2y$12$...'
ADMIN_PASSWORD=
```

bcrypt 包含 `$`，因此脚本会自动使用单引号保护。手工修改时如果漏掉单引号，Docker Compose 会进行变量插值，部署脚本会拒绝继续。

应用选择管理员密码的优先级固定为：

1. `ADMIN_PASSWORD_HASH_FILE`；
2. `ADMIN_PASSWORD_HASH`；
3. `ADMIN_PASSWORD_FILE`；
4. `ADMIN_PASSWORD`。

配置多项时高优先级项生效，脚本会给出警告。管理员账户不会写入 SQLite。

### 2.4 第二次运行：生成 Secret 并启动

保存 `.env` 后再次执行相同命令：

```bash
bash scripts/deploy.sh init
```

这次脚本会：

1. 安全读取 `.env`，不通过 `source` 执行其中的内容；
2. 检查重复配置键、管理员账户、端口、UID/GID 和宿主机路径；
3. 使用一次性 Docker helper 中的 Go `crypto/rand` 生成不同的 `SESSION_SECRET` 和 `APP_ENCRYPTION_KEY`；
4. 原子写回 `.env`，不在终端显示 Secret；
5. 创建并验证宿主机持久化目录；
6. 执行 Compose 配置校验、镜像构建和容器更新；
7. 最多等待 120 秒，直到容器健康。

脚本实际使用的 Compose 流程为：

```bash
docker compose --env-file .env config --quiet
docker compose --env-file .env build --pull
docker compose --env-file .env up -d --force-recreate
```

Secret 只在对应内联值和 `*_FILE` 引用都为空时生成。以后重复运行 `init` 或执行升级都保留原值。

### 2.5 目录权限不足

容器默认以 `10001:10001` 运行。脚本不会自动调用 `sudo`；如果目录无法创建，或所有者、写入权限与 `APP_UID`/`APP_GID` 不一致，脚本会停止并输出包含实际路径的命令，例如：

```bash
sudo mkdir -p -- "$PWD/data" "$PWD/certs"
sudo chown -R -- 10001:10001 "$PWD/data" "$PWD/certs"
sudo chmod u+rwx -- "$PWD/data" "$PWD/certs"
```

检查路径无误后执行提示命令，再重新运行：

```bash
bash scripts/deploy.sh init
```

脚本拒绝 `/`、`/etc`、`/usr`、仓库根目录等过于宽泛的目标，也拒绝目录重叠和最终路径为符号链接的配置。

## 3. 从 Git 更新部署

升级前备份 `.env`、数据目录和证书目录，然后在仓库根目录执行：

```bash
bash scripts/deploy.sh update
```

`update` 要求：

- 已存在完成配置的 `.env`；
- 当前脚本位于 Git 工作树根目录；
- tracked 文件没有未提交或已暂存的修改。

满足条件后，脚本执行 `git pull --ff-only`，再使用更新后的脚本复用完整 `init` 部署流程。Git 拉取失败时不会继续构建或更新容器。

脚本不会运行 `git reset`、不会覆盖本地修改、不会删除 Volume，也不会执行 `docker compose down -v`。

## 4. `.env` 与环境变量的关系

Compose 推荐部署只维护仓库根目录的一份 `.env`：

- Compose 使用它解析 `APP_PORT`、`DATA_HOST_DIR`、`CERTS_HOST_DIR`、`APP_UID` 和 `APP_GID`；
- `compose.yaml` 的 `env_file: .env` 再把应用运行配置传入容器；
- 修改 `.env` 后必须重新执行 `bash scripts/deploy.sh init`，单独 `docker compose restart` 不会可靠地更新容器环境。

不要在日常部署命令上重复写 `-e SESSION_SECRET=...`。这会让配置来源分散，也容易在 Shell 历史、进程参数或自动化日志中暴露 Secret。

关键字段如下：

| 配置 | 谁来填写 | 说明 |
| --- | --- | --- |
| `ADMIN_USERNAME` | 用户 | 单管理员登录名，不能为空 |
| 四种 `ADMIN_PASSWORD*` | 用户 | 至少配置一种，推荐 bcrypt 哈希或只读 Secret 文件 |
| `SESSION_SECRET` | 脚本 | 会话签名密钥，首次生成后长期复用 |
| `APP_ENCRYPTION_KEY` | 脚本 | DNS 凭据加密密钥，首次生成后长期复用 |
| `APP_PORT` | 用户 | 宿主机端口，容器内仍为 `8080` |
| `DATA_HOST_DIR` | 用户 | 宿主机应用数据目录，映射到 `/data` |
| `CERTS_HOST_DIR` | 用户 | 宿主机证书目录，映射到 `/certs` |
| `APP_UID` / `APP_GID` | 用户 | 容器进程及持久化目录所有者，默认 `10001:10001` |
| `DEFAULT_CA` | 用户可选 | CA 预设或不含凭据、片段的 HTTPS Directory URL |
| `DEFAULT_ACME_EMAIL` | 用户可选 | ACME 账户邮箱 |
| `SESSION_COOKIE_SECURE` | 用户 | HTTPS 生产环境保持 `true` |

`.env.example` 包含其余字段及逐项中文注释。容器内 `DATA_DIR=/data` 和 `CERT_OUTPUT_DIR=/certs` 必须保持不变；自定义宿主机路径只修改 `*_HOST_DIR`。

修改 `SESSION_SECRET` 会让已有登录会话失效。修改 `APP_ENCRYPTION_KEY` 可能导致数据库中已有 DNS 凭据无法解密，修改前必须备份数据。

### 4.1 使用只读 Secret 文件

高级部署可以设置 `ADMIN_PASSWORD_HASH_FILE`、`SESSION_SECRET_FILE` 和 `APP_ENCRYPTION_KEY_FILE`。这些值填写容器内路径，例如 `/run/secrets/session_secret`，并通过单独的 Compose override 或平台 Secret 配置将宿主机文件只读挂载进去。

一旦设置对应 `*_FILE`，脚本不会生成内联值。默认 `compose.yaml` 不猜测宿主机 Secret 文件位置，因此不会自动增加这些挂载。

## 5. 自定义证书输出目录

默认配置使用项目根目录下的相对目录：

```env
CERTS_HOST_DIR=./certs
```

Compose 始终挂载为：

```text
<项目根目录>/certs:/certs
```

假设证书安全目录名为 `example-com`，宿主机文件为：

```text
./certs/example-com/cert.pem
./certs/example-com/chain.pem
./certs/example-com/fullchain.pem
./certs/example-com/privkey.pem
./certs/example-com/metadata.json
./certs/example-com/.renewed
```

其他业务容器只读挂载宿主机目录，不要挂载 CertMate 的 `/data/acme` 内部目录：

```yaml
services:
  nginx:
    volumes:
      - ./certs:/etc/nginx/certs:ro
```

## 6. 配置生效边界

以下配置在创建容器时读取，修改后重新运行部署脚本：

- 端口和宿主机目录；
- 管理员账户；
- Session 与应用加密密钥；
- ACME、自签名、可信代理和日志开关；
- OpenSSL 与 acme.sh 路径。

管理后台中的续签 Cron、时区、最大并发、重试策略、单证书续签选项和 DNS 凭据保存后会动态生效，不需要重启容器。

## 7. 裸 `docker build` / `docker run`（高级）

推荐脚本只管理 Compose。如果环境必须使用裸 Docker，可以复用已经初始化完成的 `.env`：

```bash
docker build --build-arg VERSION=local -t certmate:local .

docker run -d \
  --name certmate \
  --restart unless-stopped \
  --user 10001:10001 \
  --env-file ./.env \
  -p 8080:8080 \
  -v "$(pwd)/data:/data" \
  -v "$(pwd)/certs:/certs" \
  --read-only \
  --tmpfs /tmp:size=64m,mode=1770,uid=10001,gid=10001 \
  --security-opt no-new-privileges:true \
  --cap-drop ALL \
  certmate:local
```

裸 `docker run` 不读取 Compose 的 `DATA_HOST_DIR`、`CERTS_HOST_DIR` 和 `APP_PORT` 映射语义，必须在 `-p`、`-v` 和 `--user` 参数中显式使用相同值。不要通过 `--build-arg` 传递运行时 Secret。

## 8. 备份、停止与排查

升级前应同时备份：

- `.env` 或外部 Secret；
- `DATA_HOST_DIR`；
- `CERTS_HOST_DIR`。

常用只读或可恢复操作：

```bash
docker compose ps
docker compose logs --tail=200 certmate
docker compose stop certmate
docker compose start certmate
```

应用启动时会执行向前数据库迁移，并将遗留的 `running` 任务标记为 `interrupted`。不要让多个 CertMate 实例共享同一 SQLite 与证书目录。

## 9. 验收清单

- `bash scripts/deploy.sh init` 最终报告健康；
- `docker compose ps` 显示 `certmate` 为 healthy；
- 浏览器能够通过预期地址打开页面并使用自定义管理员账户登录；
- 重启容器后 SQLite、acme.sh 状态和证书仍存在；
- `CERTS_HOST_DIR` 中能够看到签发后的证书文件；
- 其他容器只读挂载证书目录；
- `.env` 权限为 `0600` 且未提交到 Git；
- 容器未挂载 Docker Socket，未获得 root 或额外 capabilities；
- 生产环境通过 HTTPS 反向代理访问并保持 `SESSION_COOKIE_SECURE=true`。

更多安全边界与报告方式见 [SECURITY.md](../SECURITY.md)。

## 10. 常见问题

- **第一次运行没有启动 Docker**：这是正常的两阶段流程。先编辑新生成的 `.env`，然后再次运行 `bash scripts/deploy.sh init`。
- **提示目录权限不匹配**：检查脚本打印的路径后执行其 `sudo mkdir/chown/chmod` 命令，再重新运行。
- **提示 bcrypt 必须加单引号**：把配置写成 `ADMIN_PASSWORD_HASH='$2y$...'`。
- **登录后仍返回登录页**：生产 Secure Cookie 需要 HTTPS。本机隔离试用可临时设置 `SESSION_COOKIE_SECURE=false`。
- **更新被拒绝**：先查看 `git status` 并妥善处理 tracked 文件修改；脚本不会自动覆盖或清理它们。
- **容器启动失败**：运行 `docker compose logs --tail=200 certmate`；不要把包含 Secret 的 `.env` 内容粘贴到公开问题中。
