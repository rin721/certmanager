#!/usr/bin/env bash

set -Eeuo pipefail

# 部署配置包含高敏感值，新建文件必须默认仅对当前用户可读写。
umask 077

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly PROJECT_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd -P)"
readonly ENV_FILE="${PROJECT_ROOT}/.env"
readonly ENV_EXAMPLE_FILE="${PROJECT_ROOT}/.env.example"
readonly SERVICE_NAME="certmate"
readonly SETUP_HELPER_IMAGE="certmate-setup-helper:local"
readonly HEALTH_TIMEOUT_SECONDS=120
readonly HEALTH_POLL_SECONDS=2

ENV_TEMP_FILE=""
SETUP_HELPER_READY=false
declare -A ENV_VALUES=()
declare -A ENV_RAW_VALUES=()
declare -A ENV_KEY_LINES=()

cleanup() {
    if [[ -n "${ENV_TEMP_FILE}" && -f "${ENV_TEMP_FILE}" ]]; then
        rm -f -- "${ENV_TEMP_FILE}"
    fi
}
trap cleanup EXIT

log() {
    printf '==> %s\n' "$*"
}

warn() {
    printf '警告：%s\n' "$*" >&2
}

die() {
    printf '错误：%s\n' "$*" >&2
    exit 1
}

usage() {
    cat <<'EOF'
CertMate Docker Compose 部署脚本

用法：
  bash scripts/deploy.sh init    初始化配置或按现有配置构建并启动服务
  bash scripts/deploy.sh update  执行 git pull --ff-only 后构建并更新服务
  bash scripts/deploy.sh configure-admin [用户名]
                                 交互输入密码并保存 bcrypt 哈希
  bash scripts/deploy.sh help    显示帮助

首次执行 init 只会复制 .env.example 为 .env，然后停止并提示人工配置。
完成 .env 后再次执行 init，脚本才会生成 Secret、校验目录并启动服务。
EOF
}

require_command() {
    local command_name=$1
    command -v "${command_name}" >/dev/null 2>&1 || die "缺少命令 ${command_name}，请先安装后重试。"
}

trim_whitespace() {
    local value=$1
    value="${value#"${value%%[![:space:]]*}"}"
    value="${value%"${value##*[![:space:]]}"}"
    printf '%s' "${value}"
}

decode_env_value() {
    local value
    value="$(trim_whitespace "$1")"

    if [[ ${#value} -ge 2 && "${value:0:1}" == "'" && "${value: -1}" == "'" ]]; then
        printf '%s' "${value:1:${#value}-2}"
        return
    fi
    if [[ ${#value} -ge 2 && "${value:0:1}" == '"' && "${value: -1}" == '"' ]]; then
        printf '%s' "${value:1:${#value}-2}"
        return
    fi
    if [[ "${value}" =~ ^(.*[^[:space:]])[[:space:]]+#.*$ ]]; then
        value=${BASH_REMATCH[1]}
    fi
    printf '%s' "${value}"
}

parse_env_file() {
    local line line_number=0 key raw_value
    ENV_VALUES=()
    ENV_RAW_VALUES=()
    ENV_KEY_LINES=()

    while IFS= read -r line || [[ -n "${line}" ]]; do
        line_number=$((line_number + 1))
        line=${line%$'\r'}
        [[ "${line}" =~ ^[[:space:]]*$ || "${line}" =~ ^[[:space:]]*# ]] && continue
        if [[ "${line}" =~ ^[[:space:]]*([A-Za-z_][A-Za-z0-9_]*)[[:space:]]*=(.*)$ ]]; then
            key=${BASH_REMATCH[1]}
            raw_value=${BASH_REMATCH[2]}
            if [[ -n "${ENV_KEY_LINES[${key}]:-}" ]]; then
                die ".env 中的 ${key} 重复定义（第 ${ENV_KEY_LINES[${key}]} 行和第 ${line_number} 行）。"
            fi
            ENV_KEY_LINES[${key}]=${line_number}
            ENV_RAW_VALUES[${key}]="$(trim_whitespace "${raw_value}")"
            ENV_VALUES[${key}]="$(decode_env_value "${raw_value}")"
        fi
    done < "${ENV_FILE}"
}

env_value() {
    local key=$1 fallback=${2:-}
    if [[ -v "ENV_VALUES[${key}]" ]]; then
        printf '%s' "${ENV_VALUES[${key}]}"
    else
        printf '%s' "${fallback}"
    fi
}

write_env_value() {
    local key=$1 value=$2
    ENV_TEMP_FILE="$(mktemp "${ENV_FILE}.tmp.XXXXXX")" || die "无法在 .env 所在目录创建临时文件。"
    if ! awk -v target="${key}" -v replacement="${key}=${value}" '
        BEGIN { found = 0 }
        {
            comparable = $0
            sub(/\r$/, "", comparable)
            if (comparable ~ "^[[:space:]]*" target "[[:space:]]*=") {
                print replacement
                found = 1
                next
            }
            print $0
        }
        END {
            if (!found) {
                print replacement
            }
        }
    ' "${ENV_FILE}" > "${ENV_TEMP_FILE}"; then
        die "更新 ${key} 失败。"
    fi
    chmod 600 "${ENV_TEMP_FILE}" || die "无法保护临时配置文件权限。"
    mv -f -- "${ENV_TEMP_FILE}" "${ENV_FILE}" || die "无法原子替换 .env。"
    ENV_TEMP_FILE=""
    ENV_RAW_VALUES[${key}]=${value}
    ENV_VALUES[${key}]="$(decode_env_value "${value}")"
}

write_admin_credentials() {
    local username=$1 password_hash=$2
    ENV_TEMP_FILE="$(mktemp "${ENV_FILE}.tmp.XXXXXX")" || die "无法在 .env 所在目录创建临时文件。"
    if ! awk -v username="${username}" -v password_hash="'${password_hash}'" '
        BEGIN {
            replacement["ADMIN_USERNAME"] = "ADMIN_USERNAME=" username
            replacement["ADMIN_PASSWORD_HASH_FILE"] = "ADMIN_PASSWORD_HASH_FILE="
            replacement["ADMIN_PASSWORD_HASH"] = "ADMIN_PASSWORD_HASH=" password_hash
            replacement["ADMIN_PASSWORD_FILE"] = "ADMIN_PASSWORD_FILE="
            replacement["ADMIN_PASSWORD"] = "ADMIN_PASSWORD="
        }
        {
            comparable = $0
            sub(/\r$/, "", comparable)
            if (comparable ~ /^[[:space:]]*[A-Za-z_][A-Za-z0-9_]*[[:space:]]*=/) {
                key = comparable
                sub(/^[[:space:]]*/, "", key)
                sub(/[[:space:]]*=.*$/, "", key)
                if (key in replacement) {
                    print replacement[key]
                    written[key] = 1
                    next
                }
            }
            print $0
        }
        END {
            order[1] = "ADMIN_USERNAME"
            order[2] = "ADMIN_PASSWORD_HASH_FILE"
            order[3] = "ADMIN_PASSWORD_HASH"
            order[4] = "ADMIN_PASSWORD_FILE"
            order[5] = "ADMIN_PASSWORD"
            for (position = 1; position <= 5; position++) {
                key = order[position]
                if (!written[key]) {
                    print replacement[key]
                }
            }
        }
    ' "${ENV_FILE}" > "${ENV_TEMP_FILE}"; then
        die "更新管理员账户配置失败。"
    fi
    chmod 600 "${ENV_TEMP_FILE}" || die "无法保护临时配置文件权限。"
    mv -f -- "${ENV_TEMP_FILE}" "${ENV_FILE}" || die "无法原子替换 .env。"
    ENV_TEMP_FILE=""
    parse_env_file
}

configure_admin_credentials() {
    local requested_username=${1:-} username password password_confirmation password_hash

    if [[ -n "${requested_username}" ]]; then
        username=${requested_username}
    else
        [[ -t 0 && -t 1 ]] || die "当前不是交互终端；请执行 bash scripts/deploy.sh configure-admin <用户名> 并在终端中输入密码。"
        read -r -p "管理员用户名 [$(env_value ADMIN_USERNAME admin)]：" username
        username=${username:-$(env_value ADMIN_USERNAME admin)}
    fi
    [[ "${username}" =~ ^[A-Za-z0-9._@-]{1,64}$ ]] || die "管理员用户名只能包含字母、数字、点、下划线、@ 和连字符，长度为 1-64。"

    build_setup_helper
    [[ "${-}" != *x* ]] || set +x
    printf '管理员密码（输入内容不会显示）：' >&2
    if ! IFS= read -r -s password; then
        printf '\n' >&2
        die "读取管理员密码失败。"
    fi
    printf '\n再次输入管理员密码：' >&2
    if ! IFS= read -r -s password_confirmation; then
        unset password
        printf '\n' >&2
        die "读取确认密码失败。"
    fi
    printf '\n' >&2
    if [[ -z "${password}" ]]; then
        unset password password_confirmation
        die "管理员密码不能为空。"
    fi
    if [[ "${password}" != "${password_confirmation}" ]]; then
        unset password password_confirmation
        die "两次输入的管理员密码不一致。"
    fi
    if ! password_hash="$(printf '%s\n' "${password}" | run_setup_helper hash-password)"; then
        unset password password_confirmation
        die "管理员密码哈希生成失败。"
    fi
    unset password password_confirmation
    [[ "${password_hash}" =~ ^\$2[aby]\$[0-9]{2}\$[./A-Za-z0-9]{53}$ ]] || die "Docker 初始化工具未返回有效的 bcrypt 哈希。"

    write_admin_credentials "${username}" "${password_hash}"
    log "已保存管理员 ${username} 的 bcrypt 哈希，并清空其他管理员密码来源。"
}

ensure_admin_config() {
    local key
    for key in ADMIN_PASSWORD_HASH_FILE ADMIN_PASSWORD_HASH ADMIN_PASSWORD_FILE ADMIN_PASSWORD; do
        if [[ -n "$(env_value "${key}")" ]]; then
            return
        fi
    done
    [[ -t 0 && -t 1 ]] || die "尚未配置管理员密码。请在交互终端运行 bash scripts/deploy.sh configure-admin <用户名>。"
    printf '尚未配置管理员账户，现在进入安全配置。\n'
    configure_admin_credentials
}

build_setup_helper() {
    if [[ "${SETUP_HELPER_READY}" == true ]]; then
        return
    fi
    require_command docker
    log "构建一次性 Docker 初始化工具（宿主机无需安装 Apache 或 OpenSSL）。"
    docker build --target setup-helper --tag "${SETUP_HELPER_IMAGE}" "${PROJECT_ROOT}" || die "构建 Docker 初始化工具失败。"
    SETUP_HELPER_READY=true
}

run_setup_helper() {
    local operation=$1
    build_setup_helper
    docker run --rm -i --network none --read-only --security-opt no-new-privileges:true --cap-drop ALL "${SETUP_HELPER_IMAGE}" "${operation}"
}

generate_secret() {
    local secret
    secret="$(run_setup_helper random-secret)" || die "生成随机 Secret 失败。"
    [[ "${secret}" =~ ^[0-9a-f]{64}$ ]] || die "Docker 初始化工具未返回预期的 32 字节随机值。"
    printf '%s' "${secret}"
}

ensure_secret() {
    local value_key=$1 file_key=$2 value file_reference generated_secret
    value="$(env_value "${value_key}")"
    file_reference="$(env_value "${file_key}")"
    if [[ -n "${file_reference}" || -n "${value}" ]]; then
        return
    fi

    build_setup_helper
    generated_secret="$(generate_secret)"
    if [[ "${value_key}" == "APP_ENCRYPTION_KEY" && "${generated_secret}" == "$(env_value SESSION_SECRET)" ]]; then
        generated_secret="$(generate_secret)"
        [[ "${generated_secret}" != "$(env_value SESSION_SECRET)" ]] || die "两个随机 Secret 意外相同，请重新运行。"
    fi
    write_env_value "${value_key}" "${generated_secret}"
    log "已生成并保存 ${value_key}（不会显示真实值）。"
}

validate_sensitive_quoting() {
    local key raw_value
    for key in ADMIN_PASSWORD_HASH ADMIN_PASSWORD SESSION_SECRET APP_ENCRYPTION_KEY; do
        raw_value=${ENV_RAW_VALUES[${key}]:-}
        if [[ "${raw_value}" == *'$'* && !( "${raw_value}" == \'*\' ) ]]; then
            die "${key} 包含 \$ 时必须使用单引号，例如 ${key}='值'，否则 Docker Compose 会执行变量插值。"
        fi
    done
}

validate_admin_config() {
    local username source key configured_sources=0 password_hash
    username="$(env_value ADMIN_USERNAME admin)"
    [[ -n "$(trim_whitespace "${username}")" ]] || die "ADMIN_USERNAME 不能为空。"
    [[ ! "${username}" =~ [[:space:]] ]] || die "ADMIN_USERNAME 不能包含空白字符。"

    for key in ADMIN_PASSWORD_HASH_FILE ADMIN_PASSWORD_HASH ADMIN_PASSWORD_FILE ADMIN_PASSWORD; do
        if [[ -n "$(env_value "${key}")" ]]; then
            configured_sources=$((configured_sources + 1))
            source=${source:-${key}}
        fi
    done
    (( configured_sources > 0 )) || die "必须配置 ADMIN_PASSWORD_HASH_FILE、ADMIN_PASSWORD_HASH、ADMIN_PASSWORD_FILE 或 ADMIN_PASSWORD 中的一项。"
    if (( configured_sources > 1 )); then
        warn "检测到多个管理员密码来源；应用会按既有优先级使用 ${source}。"
    fi

    password_hash="$(env_value ADMIN_PASSWORD_HASH)"
    if [[ -n "${password_hash}" && ! "${password_hash}" =~ ^\$2[aby]\$[0-9]{2}\$[./A-Za-z0-9]{53}$ ]]; then
        die "ADMIN_PASSWORD_HASH 不是有效的 bcrypt 格式。"
    fi
    if [[ -n "$(env_value ADMIN_PASSWORD)" ]]; then
        warn "生产环境正在使用明文 ADMIN_PASSWORD，建议改用单引号保护的 ADMIN_PASSWORD_HASH。"
    fi
}

validate_integer_range() {
    local key=$1 value=$2 minimum=$3 maximum=$4
    [[ "${value}" =~ ^[0-9]+$ ]] || die "${key} 必须是整数。"
    (( 10#${value} >= minimum && 10#${value} <= maximum )) || die "${key} 必须在 ${minimum}-${maximum} 范围内。"
}

resolve_host_path() {
    local configured_path=$1 candidate_path resolved_path
    [[ -n "${configured_path}" ]] || die "宿主机目录不能为空。"
    [[ "${configured_path}" != *'$'* && "${configured_path}" != '~'* ]] || die "宿主机目录必须是明确路径，不能包含变量或 ~。"
    if [[ "${configured_path}" == /* ]]; then
        candidate_path=${configured_path}
    else
        candidate_path="${PROJECT_ROOT}/${configured_path}"
    fi
    [[ ! -L "${candidate_path}" ]] || die "宿主机目录不能是符号链接：${configured_path}"
    resolved_path="$(realpath -m -- "${candidate_path}")" || die "无法解析宿主机目录：${configured_path}"
    case "${resolved_path}" in
        /|/bin|/boot|/data|/dev|/etc|/home|/lib|/lib64|/media|/mnt|/opt|/proc|/root|/run|/sbin|/srv|/sys|/tmp|/usr|/var|/var/lib|/var/log|"${PROJECT_ROOT}")
            die "拒绝使用过于宽泛或危险的宿主机目录：${resolved_path}"
            ;;
    esac
    printf '%s' "${resolved_path}"
}

directory_ready_for_container() {
    local directory=$1 expected_uid=$2 expected_gid=$3 owner_uid owner_gid mode owner_mode
    owner_uid="$(stat -c '%u' -- "${directory}")" || return 1
    owner_gid="$(stat -c '%g' -- "${directory}")" || return 1
    mode="$(stat -c '%a' -- "${directory}")" || return 1
    owner_mode=${mode: -3:1}
    [[ "${owner_uid}" == "${expected_uid}" && "${owner_gid}" == "${expected_gid}" ]] || return 1
    (( (10#${owner_mode} & 3) == 3 ))
}

print_permission_commands() {
    local uid=$1 gid=$2 data_path=$3 certs_path=$4
    printf '\n请由有权限的管理员执行以下命令，然后重新运行部署脚本：\n' >&2
    printf '  sudo mkdir -p -- %q %q\n' "${data_path}" "${certs_path}" >&2
    printf '  sudo chown -R -- %q %q %q\n' "${uid}:${gid}" "${data_path}" "${certs_path}" >&2
    printf '  sudo chmod u+rwx -- %q %q\n\n' "${data_path}" "${certs_path}" >&2
}

prepare_host_directories() {
    local data_config certs_config app_uid app_gid data_path certs_path creation_failed=false permission_failed=false
    data_config="$(env_value DATA_HOST_DIR ./data)"
    certs_config="$(env_value CERTS_HOST_DIR ./certs)"
    app_uid="$(env_value APP_UID 10001)"
    app_gid="$(env_value APP_GID 10001)"

    validate_integer_range APP_UID "${app_uid}" 1 2147483647
    validate_integer_range APP_GID "${app_gid}" 1 2147483647
    data_path="$(resolve_host_path "${data_config}")"
    certs_path="$(resolve_host_path "${certs_config}")"
    if [[ "${data_path}" == "${certs_path}" || "${data_path}" == "${certs_path}/"* || "${certs_path}" == "${data_path}/"* ]]; then
        die "DATA_HOST_DIR 与 CERTS_HOST_DIR 必须是彼此独立的目录。"
    fi

    mkdir -p -- "${data_path}" 2>/dev/null || creation_failed=true
    mkdir -p -- "${certs_path}" 2>/dev/null || creation_failed=true
    if [[ "${creation_failed}" == true ]]; then
        print_permission_commands "${app_uid}" "${app_gid}" "${data_path}" "${certs_path}"
        die "无法创建宿主机持久化目录。"
    fi
    directory_ready_for_container "${data_path}" "${app_uid}" "${app_gid}" || permission_failed=true
    directory_ready_for_container "${certs_path}" "${app_uid}" "${app_gid}" || permission_failed=true
    if [[ "${permission_failed}" == true ]]; then
        print_permission_commands "${app_uid}" "${app_gid}" "${data_path}" "${certs_path}"
        die "宿主机目录的所有者或写入权限与 APP_UID/APP_GID 不一致。"
    fi
    log "宿主机数据目录：${data_path}"
    log "宿主机证书目录：${certs_path}"
}

validate_runtime_config() {
    local app_port
    validate_sensitive_quoting
    app_port="$(env_value APP_PORT 8080)"
    validate_integer_range APP_PORT "${app_port}" 1 65535

    [[ "$(env_value DATA_DIR /data)" == "/data" ]] || die "Compose 部署时 DATA_DIR 必须保持 /data。"
    [[ "$(env_value CERT_OUTPUT_DIR /certs)" == "/certs" ]] || die "Compose 部署时 CERT_OUTPUT_DIR 必须保持 /certs。"
}

validate_secret_config() {
    local session_secret encryption_key
    session_secret="$(env_value SESSION_SECRET)"
    if [[ -z "$(env_value SESSION_SECRET_FILE)" && ${#session_secret} -lt 32 ]]; then
        die "SESSION_SECRET 至少需要 32 字节。"
    fi
    encryption_key="$(env_value APP_ENCRYPTION_KEY)"
    if [[ -z "$(env_value APP_ENCRYPTION_KEY_FILE)" && ${#encryption_key} -lt 32 ]]; then
        die "APP_ENCRYPTION_KEY 至少需要 32 字节。"
    fi
    if [[ -z "$(env_value SESSION_SECRET_FILE)" && -z "$(env_value APP_ENCRYPTION_KEY_FILE)" && "${session_secret}" == "${encryption_key}" ]]; then
        die "SESSION_SECRET 和 APP_ENCRYPTION_KEY 必须使用不同的值。"
    fi
}

show_service_logs() {
    docker compose --env-file "${ENV_FILE}" logs --tail=100 "${SERVICE_NAME}" >&2 || true
}

show_compose_start_help() {
    local app_port published_containers
    app_port="$(env_value APP_PORT 8080)"

    cat >&2 <<EOF

启动排查：如果上方错误包含 "port is already allocated"，说明宿主机端口 ${app_port} 已被占用。
可先查看占用该端口的 Docker 容器：
  docker ps --filter publish=${app_port} --format 'table {{.Names}}\t{{.Ports}}'

若该端口应由其他服务使用，请在 .env 中只修改 APP_PORT，例如：
  APP_PORT=8081
  LISTEN_ADDR=:8080

APP_PORT 是宿主机访问端口；Compose 下 LISTEN_ADDR 必须保持容器内的 :8080。
修改后重新运行：bash scripts/deploy.sh init
EOF

    published_containers="$(docker ps --filter "publish=${app_port}" --format '{{.Names}}: {{.Ports}}' 2>/dev/null || true)"
    if [[ -n "${published_containers}" ]]; then
        printf '\n当前 Docker 端口占用：\n%s\n' "${published_containers}" >&2
    fi
}

wait_for_health() {
    local container_id state elapsed_seconds=0
    container_id="$(docker compose --env-file "${ENV_FILE}" ps -q "${SERVICE_NAME}")"
    [[ -n "${container_id}" ]] || {
        show_service_logs
        die "未找到 ${SERVICE_NAME} 容器。"
    }

    while (( elapsed_seconds < HEALTH_TIMEOUT_SECONDS )); do
        state="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "${container_id}" 2>/dev/null || true)"
        case "${state}" in
            healthy)
                log "CertMate 已启动并通过健康检查。"
                return
                ;;
            unhealthy|exited|dead)
                show_service_logs
                die "CertMate 容器状态为 ${state}。"
                ;;
        esac
        sleep "${HEALTH_POLL_SECONDS}"
        elapsed_seconds=$((elapsed_seconds + HEALTH_POLL_SECONDS))
    done
    show_service_logs
    die "等待 CertMate 健康检查超时（${HEALTH_TIMEOUT_SECONDS} 秒）。"
}

deploy_compose() {
    require_command docker
    docker compose version >/dev/null 2>&1 || die "需要 Docker Compose v2（docker compose）。"
    cd -- "${PROJECT_ROOT}"
    log "校验 Docker Compose 配置。"
    docker compose --env-file "${ENV_FILE}" config --quiet || die "Docker Compose 配置校验失败。"
    log "构建 CertMate 镜像。"
    docker compose --env-file "${ENV_FILE}" build --pull || die "Docker Compose 构建失败。"
    log "创建或更新 CertMate 服务。"
    if ! docker compose --env-file "${ENV_FILE}" up -d --force-recreate; then
        show_service_logs
        show_compose_start_help
        die "Docker Compose 启动失败。"
    fi
    wait_for_health
    printf '\n管理地址：http://localhost:%s\n' "$(env_value APP_PORT 8080)"
    printf '生产环境请通过 HTTPS 反向代理访问，并妥善备份 .env、数据目录和证书目录。\n'
}

initialize() {
    [[ -f "${ENV_EXAMPLE_FILE}" && ! -L "${ENV_EXAMPLE_FILE}" ]] || die "找不到普通配置模板 ${ENV_EXAMPLE_FILE}。"
    [[ ! -L "${ENV_FILE}" ]] || die ".env 不能是符号链接。"
    if [[ ! -e "${ENV_FILE}" ]]; then
        cp -- "${ENV_EXAMPLE_FILE}" "${ENV_FILE}" || die "复制 .env.example 失败。"
        chmod 600 "${ENV_FILE}" || die "无法设置 .env 权限。"
        cat <<'EOF'
已创建 .env，本次运行按设计停止，不会生成 Secret 或启动 Docker。

请先编辑 .env，至少确认：
  1. DATA_HOST_DIR（宿主机数据目录）
  2. CERTS_HOST_DIR（宿主机证书目录）
  3. APP_PORT、APP_UID、APP_GID 是否符合部署环境

管理员账户推荐由脚本安全配置：
  bash scripts/deploy.sh configure-admin
随后按提示输入并确认明文密码；脚本只会把 bcrypt 哈希写入 .env。
如果跳过该命令，下一次交互运行 init 时也会自动提示配置。

SESSION_SECRET 和 APP_ENCRYPTION_KEY 保持为空，下一次运行会自动生成。
配置完成后再次执行：bash scripts/deploy.sh init
EOF
        return
    fi
    [[ -f "${ENV_FILE}" && ! -L "${ENV_FILE}" ]] || die ".env 必须是普通文件，不能是目录或符号链接。"
    chmod 600 "${ENV_FILE}" || die "无法保护 .env 文件权限。"

    require_command awk
    require_command mktemp
    require_command realpath
    require_command stat
    parse_env_file
    validate_sensitive_quoting
    ensure_admin_config
    validate_sensitive_quoting
    validate_admin_config
    validate_runtime_config
    prepare_host_directories
    ensure_secret SESSION_SECRET SESSION_SECRET_FILE
    ensure_secret APP_ENCRYPTION_KEY APP_ENCRYPTION_KEY_FILE
    validate_secret_config
    deploy_compose
}

update() {
    [[ -f "${ENV_FILE}" && ! -L "${ENV_FILE}" ]] || die "update 要求已有普通 .env；请先运行 init 并完成配置。"
    require_command git
    require_command realpath
    cd -- "${PROJECT_ROOT}"
    local repository_root
    repository_root="$(git rev-parse --show-toplevel 2>/dev/null)" || die "当前目录不是 Git 工作树。"
    [[ "$(realpath -m -- "${repository_root}")" == "${PROJECT_ROOT}" ]] || die "脚本所在目录不是当前 Git 工作树根目录。"
    git diff --quiet -- || die "存在未提交的 tracked 文件修改，拒绝自动更新。"
    git diff --cached --quiet -- || die "存在已暂存但未提交的修改，拒绝自动更新。"
    log "执行 fast-forward 更新。"
    git pull --ff-only || die "git pull --ff-only 失败，未继续部署。"
    exec "${BASH}" "${SCRIPT_DIR}/deploy.sh" init
}

configure_admin() {
    [[ -f "${ENV_FILE}" && ! -L "${ENV_FILE}" ]] || die "请先运行 init 创建 .env。"
    chmod 600 "${ENV_FILE}" || die "无法保护 .env 文件权限。"
    require_command awk
    require_command mktemp
    parse_env_file
    validate_sensitive_quoting
    configure_admin_credentials "${1:-}"
    cat <<'EOF'

密码哈希使用的 helper 是一次性容器，已通过 --rm 自动删除；这是正常行为。
请确认 .env 中的 DATA_HOST_DIR、CERTS_HOST_DIR 和 APP_PORT，然后启动常驻服务：
  bash scripts/deploy.sh init

启动后查看：
  docker compose ps
  docker compose logs --tail=100 certmate
EOF
}

main() {
    case "${1:-help}" in
        init)
            initialize
            ;;
        update)
            update
            ;;
        configure-admin)
            configure_admin "${2:-}"
            ;;
        help|-h|--help)
            usage
            ;;
        *)
            usage >&2
            die "未知子命令：${1}"
            ;;
    esac
}

main "$@"
