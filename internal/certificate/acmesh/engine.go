// Package acmesh 将 acme.sh 封装为受控、可审计的内部证书引擎。
package acmesh

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/mail"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/rin721/certmate/internal/certificate/parser"
	"github.com/rin721/certmate/internal/credential"
)

const maxOutput = 512 << 10

type IssueRequest struct {
	CertificateID string
	PrimaryDomain string
	Domains       []string
	KeyType       string
	ChallengeType string
	DNSProvider   string
	DNSVariables  map[string]string
	CADirectory   string
	Email         string
}

type RenewRequest struct {
	CertificateID string
	PrimaryDomain string
	KeyType       string
	Force         bool
	DNSVariables  map[string]string
}

type RevokeRequest struct {
	PrimaryDomain string
	KeyType       string
}

type Result struct {
	CertificatePEM []byte
	ChainPEM       []byte
	FullchainPEM   []byte
	PrivateKeyPEM  []byte
	Metadata       parser.Metadata
	ExitCode       int
	OutputSummary  string
}

type CertificateInfo struct {
	Output string
}

type ACMEEngine interface {
	Issue(context.Context, IssueRequest) (*Result, error)
	Renew(context.Context, RenewRequest) (*Result, error)
	Revoke(context.Context, RevokeRequest) error
	Remove(context.Context, string) error
	Info(context.Context, string) (*CertificateInfo, error)
}

type CLI struct {
	binary       string
	acmeHome     string
	challengeDir string
	tempRoot     string
	timeout      time.Duration
}

func NewCLI(binary, acmeHome, challengeDir, tempRoot string, timeout time.Duration) *CLI {
	if binary == "" {
		binary = "acme.sh"
	}
	if timeout <= 0 {
		timeout = 5 * time.Minute
	}
	return &CLI{binary: binary, acmeHome: acmeHome, challengeDir: challengeDir, tempRoot: tempRoot, timeout: timeout}
}

func (c *CLI) Issue(ctx context.Context, request IssueRequest) (*Result, error) {
	arguments, err := c.issueArguments(request)
	if err != nil {
		return nil, err
	}
	exitCode, output, err := c.run(ctx, arguments, request.DNSVariables)
	if err != nil {
		return nil, &CommandError{Operation: "issue", ExitCode: exitCode, Summary: output, Retryable: true, Cause: err}
	}
	return c.install(ctx, request.PrimaryDomain, request.KeyType, request.DNSVariables, output)
}

func (c *CLI) Renew(ctx context.Context, request RenewRequest) (*Result, error) {
	arguments, err := c.renewArguments(request)
	if err != nil {
		return nil, err
	}
	exitCode, output, err := c.run(ctx, arguments, request.DNSVariables)
	if err != nil {
		return nil, &CommandError{Operation: "renew", ExitCode: exitCode, Summary: output, Retryable: true, Cause: err}
	}
	return c.install(ctx, request.PrimaryDomain, request.KeyType, request.DNSVariables, output)
}

func (c *CLI) renewArguments(request RenewRequest) ([]string, error) {
	if err := validateDomain(request.PrimaryDomain); err != nil {
		return nil, err
	}
	arguments := append(c.baseArguments(), "--renew", "-d", request.PrimaryDomain)
	if isECC(request.KeyType) {
		arguments = append(arguments, "--ecc")
	} else if request.KeyType != "rsa-2048" && request.KeyType != "rsa-3072" {
		return nil, errors.New("不支持的 ACME 密钥类型")
	}
	if request.Force {
		arguments = append(arguments, "--force")
	}
	return arguments, nil
}

func (c *CLI) Revoke(ctx context.Context, request RevokeRequest) error {
	if err := validateDomain(request.PrimaryDomain); err != nil {
		return err
	}
	arguments := append(c.baseArguments(), "--revoke", "-d", request.PrimaryDomain)
	if isECC(request.KeyType) {
		arguments = append(arguments, "--ecc")
	}
	exitCode, output, err := c.run(ctx, arguments, nil)
	if err != nil {
		return &CommandError{Operation: "revoke", ExitCode: exitCode, Summary: output, Retryable: false, Cause: err}
	}
	return nil
}

func (c *CLI) Remove(ctx context.Context, primaryDomain string) error {
	if err := validateDomain(primaryDomain); err != nil {
		return err
	}
	exitCode, output, err := c.run(ctx, append(c.baseArguments(), "--remove", "-d", primaryDomain), nil)
	if err != nil {
		return &CommandError{Operation: "remove", ExitCode: exitCode, Summary: output, Retryable: false, Cause: err}
	}
	return nil
}

func (c *CLI) Info(ctx context.Context, primaryDomain string) (*CertificateInfo, error) {
	if err := validateDomain(primaryDomain); err != nil {
		return nil, err
	}
	_, output, err := c.run(ctx, append(c.baseArguments(), "--info", "-d", primaryDomain), nil)
	if err != nil {
		return nil, err
	}
	return &CertificateInfo{Output: output}, nil
}

func (c *CLI) issueArguments(request IssueRequest) ([]string, error) {
	if err := validateDomain(request.PrimaryDomain); err != nil {
		return nil, err
	}
	if len(request.Domains) == 0 || len(request.Domains) > 100 {
		return nil, errors.New("ACME 域名数量无效")
	}
	arguments := append(c.baseArguments(), "--issue")
	server, err := validateCA(request.CADirectory)
	if err != nil {
		return nil, err
	}
	arguments = append(arguments, "--server", server)
	address, err := mail.ParseAddress(request.Email)
	if err != nil || address.Address != request.Email || strings.ContainsAny(request.Email, "\r\n <>\"") {
		return nil, errors.New("ACME 邮箱格式无效")
	}
	arguments = append(arguments, "--accountemail", request.Email)
	for _, domain := range request.Domains {
		if err := validateDomain(domain); err != nil {
			return nil, err
		}
		arguments = append(arguments, "-d", domain)
	}
	keyLength, err := keyLength(request.KeyType)
	if err != nil {
		return nil, err
	}
	arguments = append(arguments, "--keylength", keyLength)
	switch request.ChallengeType {
	case "dns-01":
		if err := credential.ValidateCustomProviderCode(request.DNSProvider); err != nil {
			return nil, err
		}
		if len(request.DNSVariables) == 0 {
			return nil, errors.New("DNS-01 缺少 Provider 凭据")
		}
		arguments = append(arguments, "--dns", request.DNSProvider)
	case "http-01":
		for _, domain := range request.Domains {
			if strings.HasPrefix(domain, "*.") {
				return nil, errors.New("HTTP-01 不支持通配符域名")
			}
		}
		arguments = append(arguments, "--webroot", c.challengeDir)
	default:
		return nil, errors.New("仅支持 dns-01 或 http-01")
	}
	return arguments, nil
}

func (c *CLI) install(ctx context.Context, primaryDomain, keyType string, variables map[string]string, previousOutput string) (*Result, error) {
	if err := os.MkdirAll(c.tempRoot, 0o750); err != nil {
		return nil, err
	}
	tempDir, err := os.MkdirTemp(c.tempRoot, "acme-install-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tempDir)
	if err := os.Chmod(tempDir, 0o700); err != nil {
		return nil, err
	}
	paths := map[string]string{
		"cert": filepath.Join(tempDir, "cert.pem"), "chain": filepath.Join(tempDir, "chain.pem"),
		"fullchain": filepath.Join(tempDir, "fullchain.pem"), "key": filepath.Join(tempDir, "privkey.pem"),
	}
	arguments := append(c.baseArguments(), "--install-cert", "-d", primaryDomain)
	if isECC(keyType) {
		arguments = append(arguments, "--ecc")
	}
	arguments = append(arguments, "--cert-file", paths["cert"], "--ca-file", paths["chain"], "--fullchain-file", paths["fullchain"], "--key-file", paths["key"])
	exitCode, installOutput, err := c.run(ctx, arguments, variables)
	combined := strings.TrimSpace(previousOutput + "\n" + installOutput)
	if err != nil {
		return nil, &CommandError{Operation: "install", ExitCode: exitCode, Summary: combined, Retryable: true, Cause: err}
	}
	certificatePEM, err := readFile(paths["cert"])
	if err != nil {
		return nil, err
	}
	chainPEM, err := readFile(paths["chain"])
	if err != nil {
		return nil, err
	}
	fullchainPEM, err := readFile(paths["fullchain"])
	if err != nil {
		return nil, err
	}
	privateKeyPEM, err := readFile(paths["key"])
	if err != nil {
		return nil, err
	}
	certificate, metadata, err := parser.ParseCertificate(certificatePEM)
	if err != nil {
		return nil, err
	}
	if err := parser.ValidateKeyMatches(certificate, privateKeyPEM); err != nil {
		return nil, err
	}
	return &Result{CertificatePEM: certificatePEM, ChainPEM: chainPEM, FullchainPEM: fullchainPEM, PrivateKeyPEM: privateKeyPEM, Metadata: metadata, ExitCode: exitCode, OutputSummary: combined}, nil
}

func (c *CLI) baseArguments() []string {
	return []string{"--config-home", c.acmeHome, "--cert-home", filepath.Join(c.acmeHome, "certs")}
}

func (c *CLI) run(ctx context.Context, arguments []string, variables map[string]string) (int, string, error) {
	for name, value := range variables {
		if err := credential.ValidateProcessEnvironmentName(name); err != nil || value == "" {
			return -1, "", errors.New("DNS Provider 环境变量无效")
		}
	}
	commandCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	command := exec.CommandContext(commandCtx, c.binary, arguments...)
	environment := []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "HOME=/nonexistent", "LANG=C", "LC_ALL=C"}
	names := make([]string, 0, len(variables))
	for name := range variables {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		environment = append(environment, name+"="+variables[name])
	}
	command.Env = environment
	stdout, stderr := &boundedBuffer{limit: maxOutput}, &boundedBuffer{limit: maxOutput}
	command.Stdout, command.Stderr = stdout, stderr
	err := command.Run()
	output := redactOutput(strings.TrimSpace(stdout.String()+"\n"+stderr.String()), variables)
	if len(output) > 8192 {
		output = output[:8192] + "…"
	}
	if errors.Is(commandCtx.Err(), context.DeadlineExceeded) {
		return -1, output, commandCtx.Err()
	}
	if err == nil {
		return 0, output, nil
	}
	exitCode := -1
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		exitCode = exitErr.ExitCode()
	}
	return exitCode, output, err
}

type CommandError struct {
	Operation string
	ExitCode  int
	Summary   string
	Retryable bool
	Cause     error
}

func (e *CommandError) Error() string {
	return fmt.Sprintf("acme.sh %s 失败(exit=%d): %s", e.Operation, e.ExitCode, e.Summary)
}
func (e *CommandError) Unwrap() error { return e.Cause }

func validateDomain(value string) error {
	if value == "" || len(value) > 253 || strings.ContainsAny(value, "\r\n") || value != strings.ToLower(value) {
		return errors.New("ACME 域名参数无效")
	}
	if strings.HasPrefix(value, "*.") {
		value = strings.TrimPrefix(value, "*.")
	}
	if strings.Contains(value, "*") {
		return errors.New("ACME 通配符域名参数无效")
	}
	labels := strings.Split(value, ".")
	if len(labels) < 2 {
		return errors.New("ACME 域名至少需要两个标签")
	}
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return errors.New("ACME 域名标签无效")
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
				return errors.New("ACME 域名包含非法字符")
			}
		}
	}
	return nil
}

func validateCA(value string) (string, error) {
	if value == "letsencrypt" || value == "letsencrypt_test" || value == "zerossl" {
		return value, nil
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
		return "", errors.New("ACME Directory URL 必须是有效的 HTTPS URL")
	}
	return parsed.String(), nil
}

func keyLength(value string) (string, error) {
	switch value {
	case "ec-256":
		return "ec-256", nil
	case "rsa-2048":
		return "2048", nil
	case "rsa-3072":
		return "3072", nil
	default:
		return "", errors.New("不支持的 ACME 密钥类型")
	}
}

func isECC(value string) bool { return value == "ec-256" }

type boundedBuffer struct {
	buffer bytes.Buffer
	limit  int64
}

func (b *boundedBuffer) Write(value []byte) (int, error) {
	remaining := b.limit - int64(b.buffer.Len())
	if remaining <= 0 {
		return 0, errors.New("acme.sh 输出超过限制")
	}
	if int64(len(value)) > remaining {
		_, _ = b.buffer.Write(value[:remaining])
		return int(remaining), errors.New("acme.sh 输出超过限制")
	}
	return b.buffer.Write(value)
}
func (b *boundedBuffer) String() string { return b.buffer.String() }

func redactOutput(value string, variables map[string]string) string {
	secrets := make([]string, 0, len(variables))
	for _, secret := range variables {
		if secret != "" {
			secrets = append(secrets, secret)
		}
	}
	sort.Slice(secrets, func(i, j int) bool { return len(secrets[i]) > len(secrets[j]) })
	for _, secret := range secrets {
		value = strings.ReplaceAll(value, secret, "[REDACTED]")
	}
	return value
}

func readFile(filename string) ([]byte, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	value, err := io.ReadAll(io.LimitReader(file, 2<<20+1))
	if err != nil {
		return nil, err
	}
	if len(value) > 2<<20 {
		return nil, errors.New("acme.sh 安装文件过大")
	}
	return value, nil
}
