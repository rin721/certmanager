#!/usr/bin/env bash

set -Eeuo pipefail

readonly SOURCE_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
readonly TEST_PARENT="${TMPDIR:-/tmp}"
TEST_ROOT="$(mktemp -d "${TEST_PARENT%/}/certmate-deploy-test.XXXXXX")"
TEST_COUNT=0

cleanup() {
    if [[ -n "${TEST_ROOT}" && -d "${TEST_ROOT}" && "${TEST_ROOT}" == "${TEST_PARENT%/}/certmate-deploy-test."* ]]; then
        rm -rf -- "${TEST_ROOT}"
    fi
}
trap cleanup EXIT

fail() {
    printf 'FAIL: %s\n' "$*" >&2
    exit 1
}

pass() {
    TEST_COUNT=$((TEST_COUNT + 1))
    printf 'PASS: %s\n' "$*"
}

assert_contains() {
    local file=$1 expected=$2
    grep -F -- "${expected}" "${file}" >/dev/null || fail "${file} 不包含：${expected}"
}

assert_not_contains() {
    local file=$1 unexpected=$2
    if [[ -f "${file}" ]] && grep -F -- "${unexpected}" "${file}" >/dev/null; then
        fail "${file} 意外包含：${unexpected}"
    fi
}

env_value() {
    local file=$1 key=$2
    awk -F= -v target="${key}" '$1 == target { sub(/^[^=]*=/, ""); print; exit }' "${file}"
}

set_env_value() {
    local file=$1 key=$2 value=$3 replacement_file
    replacement_file="${file}.replacement"
    awk -v target="${key}" -v replacement="${key}=${value}" '
        $0 ~ "^" target "=" { print replacement; next }
        { print }
    ' "${file}" > "${replacement_file}"
    mv -- "${replacement_file}" "${file}"
}

create_mocks() {
    local workspace=$1 mock_bin
    mock_bin="${workspace}/mock-bin"
    mkdir -p -- "${mock_bin}"

    cat > "${mock_bin}/docker" <<'EOF'
#!/usr/bin/env bash
printf 'docker %s\n' "$*" >> "${MOCK_LOG}"
if [[ "${1:-}" == "inspect" ]]; then
    printf 'healthy\n'
elif [[ "${1:-}" == "compose" && " $* " == *" ps -q certmate "* ]]; then
    printf 'mock-container-id\n'
fi
EOF
    cat > "${mock_bin}/openssl" <<'EOF'
#!/usr/bin/env bash
printf 'openssl %s\n' "$*" >> "${MOCK_LOG}"
count=0
[[ -f "${MOCK_OPENSSL_COUNT}" ]] && count="$(<"${MOCK_OPENSSL_COUNT}")"
count=$((count + 1))
printf '%s' "${count}" > "${MOCK_OPENSSL_COUNT}"
if (( count % 2 == 1 )); then
    printf 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n'
else
    printf 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n'
fi
EOF
    cat > "${mock_bin}/git" <<'EOF'
#!/usr/bin/env bash
printf 'git %s\n' "$*" >> "${MOCK_LOG}"
if [[ "${1:-}" == "rev-parse" ]]; then
    printf '%s\n' "${MOCK_PROJECT_ROOT}"
elif [[ "${1:-}" == "diff" && "${MOCK_GIT_DIFF_FAILURE:-}" == "1" ]]; then
    exit 1
elif [[ "${1:-}" == "pull" && "${MOCK_GIT_PULL_FAILURE:-}" == "1" ]]; then
    exit 1
fi
EOF
    chmod +x "${mock_bin}/docker" "${mock_bin}/openssl" "${mock_bin}/git"
}

new_workspace() {
    local name=$1 workspace
    workspace="${TEST_ROOT}/${name}"
    mkdir -p -- "${workspace}/scripts"
    cp -- "${SOURCE_ROOT}/scripts/deploy.sh" "${workspace}/scripts/deploy.sh"
    cp -- "${SOURCE_ROOT}/.env.example" "${workspace}/.env.example"
    printf 'services:\n  certmate:\n    image: mock\n' > "${workspace}/compose.yaml"
    create_mocks "${workspace}"
    printf '%s' "${workspace}"
}

run_deploy() {
    local workspace=$1 output_file=$2 mode=$3
    PATH="${workspace}/mock-bin:${PATH}" \
        MOCK_LOG="${workspace}/mock.log" \
        MOCK_OPENSSL_COUNT="${workspace}/openssl.count" \
        MOCK_PROJECT_ROOT="${workspace}" \
        MOCK_GIT_DIFF_FAILURE="${MOCK_GIT_DIFF_FAILURE:-}" \
        MOCK_GIT_PULL_FAILURE="${MOCK_GIT_PULL_FAILURE:-}" \
        bash "${workspace}/scripts/deploy.sh" "${mode}" > "${output_file}" 2>&1
}

configure_common_values() {
    local workspace=$1
    mkdir -p -- "${workspace}/data" "${workspace}/certs"
    set_env_value "${workspace}/.env" ADMIN_USERNAME certadmin
    set_env_value "${workspace}/.env" ADMIN_PASSWORD "'test-password'"
    set_env_value "${workspace}/.env" DATA_HOST_DIR "${workspace}/data"
    set_env_value "${workspace}/.env" CERTS_HOST_DIR "${workspace}/certs"
    set_env_value "${workspace}/.env" APP_UID "$(id -u)"
    set_env_value "${workspace}/.env" APP_GID "$(id -g)"
}

test_first_run_stops_after_copy() {
    local workspace output_file
    workspace="$(new_workspace first-run)"
    output_file="${workspace}/output.log"
    run_deploy "${workspace}" "${output_file}" init
    [[ -f "${workspace}/.env" ]] || fail "首次运行没有创建 .env"
    [[ -z "$(env_value "${workspace}/.env" SESSION_SECRET)" ]] || fail "首次运行不应生成 SESSION_SECRET"
    [[ -z "$(env_value "${workspace}/.env" APP_ENCRYPTION_KEY)" ]] || fail "首次运行不应生成 APP_ENCRYPTION_KEY"
    assert_contains "${output_file}" "本次运行按设计停止"
    assert_not_contains "${workspace}/mock.log" "docker "
    assert_not_contains "${workspace}/mock.log" "openssl "
    pass "首次运行只复制配置并停止"
}

test_second_run_generates_once_and_deploys() {
    local workspace output_file session_secret encryption_key original_session original_encryption openssl_calls fake_hash
    workspace="$(new_workspace second-run)"
    output_file="${workspace}/output.log"
    run_deploy "${workspace}" "${output_file}" init
    configure_common_values "${workspace}"
    fake_hash='$2y$12$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
    set_env_value "${workspace}/.env" ADMIN_PASSWORD ''
    set_env_value "${workspace}/.env" ADMIN_PASSWORD_HASH "'${fake_hash}'"
    run_deploy "${workspace}" "${output_file}" init

    session_secret="$(env_value "${workspace}/.env" SESSION_SECRET)"
    encryption_key="$(env_value "${workspace}/.env" APP_ENCRYPTION_KEY)"
    [[ "${session_secret}" =~ ^[0-9a-f]{64}$ ]] || fail "SESSION_SECRET 格式错误"
    [[ "${encryption_key}" =~ ^[0-9a-f]{64}$ ]] || fail "APP_ENCRYPTION_KEY 格式错误"
    [[ "${session_secret}" != "${encryption_key}" ]] || fail "两个 Secret 不应相同"
    assert_contains "${workspace}/mock.log" "docker compose --env-file ${workspace}/.env build --pull"
    assert_contains "${workspace}/mock.log" "docker compose --env-file ${workspace}/.env up -d --force-recreate"

    original_session=${session_secret}
    original_encryption=${encryption_key}
    run_deploy "${workspace}" "${output_file}" init
    [[ "$(env_value "${workspace}/.env" SESSION_SECRET)" == "${original_session}" ]] || fail "重复运行改写了 SESSION_SECRET"
    [[ "$(env_value "${workspace}/.env" APP_ENCRYPTION_KEY)" == "${original_encryption}" ]] || fail "重复运行改写了 APP_ENCRYPTION_KEY"
    openssl_calls="$(grep -c '^openssl ' "${workspace}/mock.log")"
    [[ "${openssl_calls}" == "2" ]] || fail "重复运行不应再次调用 openssl"
    pass "第二次运行生成 Secret、部署且保持幂等"
}

test_secret_file_references_skip_generation() {
    local workspace output_file
    workspace="$(new_workspace file-secrets)"
    output_file="${workspace}/output.log"
    run_deploy "${workspace}" "${output_file}" init
    configure_common_values "${workspace}"
    set_env_value "${workspace}/.env" ADMIN_PASSWORD ''
    set_env_value "${workspace}/.env" ADMIN_PASSWORD_HASH_FILE /run/secrets/admin_password_hash
    set_env_value "${workspace}/.env" SESSION_SECRET_FILE /run/secrets/session_secret
    set_env_value "${workspace}/.env" APP_ENCRYPTION_KEY_FILE /run/secrets/app_encryption_key
    run_deploy "${workspace}" "${output_file}" init
    assert_not_contains "${workspace}/mock.log" "openssl "
    pass "Secret 文件引用不会生成内联值"
}

test_invalid_configuration_stops_before_docker() {
    local workspace output_file fake_hash
    workspace="$(new_workspace invalid-config)"
    output_file="${workspace}/output.log"
    run_deploy "${workspace}" "${output_file}" init
    configure_common_values "${workspace}"
    printf '\nAPP_PORT=9090\n' >> "${workspace}/.env"
    if run_deploy "${workspace}" "${output_file}" init; then
        fail "重复配置键应导致失败"
    fi
    assert_contains "${output_file}" "APP_PORT 重复定义"
    assert_not_contains "${workspace}/mock.log" "docker "

    workspace="$(new_workspace invalid-bcrypt)"
    output_file="${workspace}/output.log"
    run_deploy "${workspace}" "${output_file}" init
    configure_common_values "${workspace}"
    fake_hash='$2y$12$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
    set_env_value "${workspace}/.env" ADMIN_PASSWORD ''
    set_env_value "${workspace}/.env" ADMIN_PASSWORD_HASH "${fake_hash}"
    if run_deploy "${workspace}" "${output_file}" init; then
        fail "未加单引号的 bcrypt 应导致失败"
    fi
    assert_contains "${output_file}" "必须使用单引号"
    assert_not_contains "${workspace}/mock.log" "docker "

    workspace="$(new_workspace invalid-path)"
    output_file="${workspace}/output.log"
    run_deploy "${workspace}" "${output_file}" init
    configure_common_values "${workspace}"
    set_env_value "${workspace}/.env" DATA_HOST_DIR /
    if run_deploy "${workspace}" "${output_file}" init; then
        fail "危险宿主机目录应导致失败"
    fi
    assert_contains "${output_file}" "拒绝使用过于宽泛或危险的宿主机目录"
    assert_not_contains "${workspace}/mock.log" "docker "

    workspace="$(new_workspace invalid-uid)"
    output_file="${workspace}/output.log"
    run_deploy "${workspace}" "${output_file}" init
    configure_common_values "${workspace}"
    set_env_value "${workspace}/.env" APP_UID 0
    if run_deploy "${workspace}" "${output_file}" init; then
        fail "root UID 应导致失败"
    fi
    assert_contains "${output_file}" "APP_UID 必须在 1-2147483647 范围内"
    assert_not_contains "${workspace}/mock.log" "docker "

    workspace="$(new_workspace duplicate-secrets)"
    output_file="${workspace}/output.log"
    run_deploy "${workspace}" "${output_file}" init
    configure_common_values "${workspace}"
    set_env_value "${workspace}/.env" SESSION_SECRET aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    set_env_value "${workspace}/.env" APP_ENCRYPTION_KEY aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    if run_deploy "${workspace}" "${output_file}" init; then
        fail "相同的 Session 与加密 Secret 应导致失败"
    fi
    assert_contains "${output_file}" "必须使用不同的值"
    assert_not_contains "${workspace}/mock.log" "docker "

    workspace="$(new_workspace invalid-permissions)"
    output_file="${workspace}/output.log"
    run_deploy "${workspace}" "${output_file}" init
    configure_common_values "${workspace}"
    set_env_value "${workspace}/.env" APP_UID "$(( $(id -u) + 1 ))"
    if run_deploy "${workspace}" "${output_file}" init; then
        fail "目录所有者不匹配应导致失败"
    fi
    assert_contains "${output_file}" "sudo chown -R --"
    assert_not_contains "${workspace}/mock.log" "docker "
    pass "无效配置会在 Docker 启动前失败"
}

test_update_pulls_then_deploys() {
    local workspace output_file
    workspace="$(new_workspace update)"
    output_file="${workspace}/output.log"
    run_deploy "${workspace}" "${output_file}" init
    configure_common_values "${workspace}"
    set_env_value "${workspace}/.env" SESSION_SECRET aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    set_env_value "${workspace}/.env" APP_ENCRYPTION_KEY bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
    run_deploy "${workspace}" "${output_file}" update
    assert_contains "${workspace}/mock.log" "git pull --ff-only"
    assert_contains "${workspace}/mock.log" "docker compose --env-file ${workspace}/.env build --pull"
    pass "update 使用 fast-forward 更新后复用部署流程"
}

test_update_failure_stops_before_docker() {
    local workspace output_file
    workspace="$(new_workspace update-failure)"
    output_file="${workspace}/output.log"
    run_deploy "${workspace}" "${output_file}" init
    configure_common_values "${workspace}"
    set_env_value "${workspace}/.env" SESSION_SECRET aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    set_env_value "${workspace}/.env" APP_ENCRYPTION_KEY bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
    if MOCK_GIT_PULL_FAILURE=1 run_deploy "${workspace}" "${output_file}" update; then
        fail "git pull 失败后不应继续部署"
    fi
    assert_contains "${output_file}" "git pull --ff-only 失败"
    assert_not_contains "${workspace}/mock.log" "docker "
    pass "Git 更新失败时不启动 Docker"
}

test_first_run_stops_after_copy
test_second_run_generates_once_and_deploys
test_secret_file_references_skip_generation
test_invalid_configuration_stops_before_docker
test_update_pulls_then_deploys
test_update_failure_stops_before_docker

printf '\n全部 %s 组部署脚本测试通过。\n' "${TEST_COUNT}"
