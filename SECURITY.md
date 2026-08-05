# CertMate 安全策略

## 支持范围

安全修复仅针对当前主分支和最新发布版本。部署方应及时更新 Go/Node 基础镜像、acme.sh、OpenSSL 与项目依赖，并运行 `make vuln`。

## 报告漏洞

请通过仓库的 GitHub Private Vulnerability Reporting / Security Advisory 私下报告。不要在公开 Issue 中提交密码、Token、私钥、Cookie、数据库或可利用细节。报告应包含受影响版本、最小复现、影响和建议修复；维护者会先确认收件，再协调披露。

## 部署基线

- 只通过 HTTPS 和受限网络暴露管理界面；保持 `SESSION_COOKIE_SECURE=true`。
- 为 Session、应用加密和管理员密码使用不同的高熵 Secret，优先使用只读 Secret 文件。
- 不授予 Docker Socket、root、额外 Linux capabilities 或宿主机宽泛目录权限。
- `/data` 与 `/certs` 仅允许专用 UID/GID 访问；私钥在 Linux 上必须为 `0600`。
- `TRUST_PROXY=true` 时只配置真实反向代理的最小 CIDR，边缘应覆盖而不是追加外部转发头。
- 管理端口不得直连公网；HTTP-01 只转发 `/.well-known/acme-challenge/`。
- 定期备份 SQLite、acme.sh 状态和证书目录，并演练恢复。

## Secret 与日志

CertMate 不把管理员密码写入数据库，不把证书私钥正文存入 SQLite。DNS Secret 使用应用主密钥进行 AES-GCM 加密或仅保存环境变量引用。日志、任务输出和审计记录不得包含密码、Token、Cookie、DNS Secret 或私钥；发生疑似泄漏时应立即轮换相关 Secret 和证书。

DNS 凭据页面的“测试”是本地安全校验，只验证密文解密或环境变量引用，不向第三方 DNS Provider 发起在线请求，也不会修改 DNS 记录。ACME Directory URL 只接受预设值或不含凭据/片段的 HTTPS 地址。

## 安全验证

```bash
go test -race ./...
go vet ./...
go run golang.org/x/vuln/cmd/govulncheck@latest ./...
cd web && npm audit --audit-level=high --registry=https://registry.npmjs.org
make license
```

## 已知依赖公告

截至 2026-08-05，`react-router-dom` 6.30.4 的依赖审计报告 2 个中等级条目：用户控制导航路径可能导致开放跳转，以及 SSR hydration 错误反序列化。CertMate 使用声明式 `<BrowserRouter>`，不使用 data/framework router、SSR/hydration、action/loader 重定向或用户控制的跳转目标；所有导航目标均由应用内固定路由或 URL 编码后的证书 ID 构造。CI 仍保留原始审计并在出现 high/critical 时失败；维护者应在 React Router 7 系列不再引入更高等级公告后升级并移除此临时风险接受。

Docker 与反向代理控制仍需在实际部署环境验证，包括 TLS、Cookie、响应头、目录权限、备份权限和可信代理边界。
