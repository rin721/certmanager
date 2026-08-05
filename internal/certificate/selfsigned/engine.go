// Package selfsigned 通过受控 OpenSSL CLI 生成自签名证书。
package selfsigned

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/rin721/certmate/internal/certificate/parser"
)

const maxCommandOutput = 256 << 10

type Request struct {
	PrimaryDomain string
	Domains       []string
	KeyType       string
	ValidDays     int
}

type Result struct {
	CertificatePEM []byte
	PrivateKeyPEM  []byte
	Metadata       parser.Metadata
	ExitCode       int
	OutputSummary  string
}

type Engine interface {
	Issue(ctx context.Context, request Request) (*Result, error)
	Renew(ctx context.Context, request Request) (*Result, error)
}

type CLI struct {
	binary   string
	tempRoot string
	timeout  time.Duration
	now      func() time.Time
}

func NewCLI(binary, tempRoot string, timeout time.Duration) *CLI {
	if binary == "" {
		binary = "openssl"
	}
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	return &CLI{binary: binary, tempRoot: tempRoot, timeout: timeout, now: time.Now}
}

func (c *CLI) Issue(ctx context.Context, request Request) (*Result, error) {
	return c.generate(ctx, request)
}

func (c *CLI) Renew(ctx context.Context, request Request) (*Result, error) {
	return c.generate(ctx, request)
}

func (c *CLI) generate(ctx context.Context, request Request) (*Result, error) {
	if request.ValidDays < 1 || request.ValidDays > 3650 {
		return nil, errors.New("自签名证书有效天数必须在 1 到 3650 之间")
	}
	arguments, err := buildArguments(request)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(c.tempRoot, 0o750); err != nil {
		return nil, fmt.Errorf("创建证书临时根目录: %w", err)
	}
	tempDir, err := os.MkdirTemp(c.tempRoot, "selfsigned-")
	if err != nil {
		return nil, fmt.Errorf("创建证书临时目录: %w", err)
	}
	if err := os.Chmod(tempDir, 0o700); err != nil {
		_ = os.Remove(tempDir)
		return nil, err
	}
	defer os.RemoveAll(tempDir)

	configPath := filepath.Join(tempDir, "openssl.cnf")
	keyPath := filepath.Join(tempDir, "privkey.pem")
	certPath := filepath.Join(tempDir, "cert.pem")
	if err := os.WriteFile(configPath, []byte(buildConfig(request)), 0o600); err != nil {
		return nil, fmt.Errorf("写入 OpenSSL 配置: %w", err)
	}
	arguments = append(arguments, "-keyout", keyPath, "-out", certPath, "-config", configPath, "-extensions", "v3_req")

	commandCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	command := exec.CommandContext(commandCtx, c.binary, arguments...)
	command.Dir = tempDir
	command.Env = []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "HOME=/nonexistent", "LANG=C", "LC_ALL=C"}
	stdout := &limitedBuffer{limit: maxCommandOutput}
	stderr := &limitedBuffer{limit: maxCommandOutput}
	command.Stdout = stdout
	command.Stderr = stderr
	err = command.Run()
	exitCode := 0
	if err != nil {
		exitCode = -1
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			exitCode = exitErr.ExitCode()
		}
		if errors.Is(commandCtx.Err(), context.DeadlineExceeded) {
			return nil, fmt.Errorf("OpenSSL 执行超时: %w", commandCtx.Err())
		}
		return nil, &CommandError{ExitCode: exitCode, Summary: sanitizeOutput(stdout.String()+"\n"+stderr.String(), tempDir), Cause: err}
	}
	certificatePEM, err := readLimited(certPath, 2<<20)
	if err != nil {
		return nil, err
	}
	privateKeyPEM, err := readLimited(keyPath, 2<<20)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(keyPath, 0o600); err != nil {
		return nil, fmt.Errorf("设置临时私钥权限: %w", err)
	}
	metadata, err := parser.ValidateCertificateAndKey(certificatePEM, privateKeyPEM, request.Domains, c.now())
	if err != nil {
		return nil, fmt.Errorf("验证 OpenSSL 生成结果: %w", err)
	}
	return &Result{
		CertificatePEM: certificatePEM,
		PrivateKeyPEM:  privateKeyPEM,
		Metadata:       metadata,
		ExitCode:       exitCode,
		OutputSummary:  sanitizeOutput(stdout.String()+"\n"+stderr.String(), tempDir),
	}, nil
}

func buildArguments(request Request) ([]string, error) {
	arguments := []string{"req", "-x509", "-new", "-nodes", "-sha256", "-days", strconv.Itoa(request.ValidDays)}
	switch request.KeyType {
	case "ec-256":
		arguments = append(arguments, "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256")
	case "rsa-2048":
		arguments = append(arguments, "-newkey", "rsa:2048")
	case "rsa-3072":
		arguments = append(arguments, "-newkey", "rsa:3072")
	default:
		return nil, errors.New("不支持的自签名密钥类型")
	}
	return arguments, nil
}

func buildConfig(request Request) string {
	var builder strings.Builder
	builder.WriteString("[req]\nprompt = no\ndistinguished_name = dn\nx509_extensions = v3_req\n\n[dn]\nCN = ")
	builder.WriteString(request.PrimaryDomain)
	builder.WriteString("\n\n[v3_req]\nbasicConstraints = critical,CA:FALSE\nkeyUsage = critical,digitalSignature,keyEncipherment\nextendedKeyUsage = serverAuth\nsubjectAltName = @alt_names\n\n[alt_names]\n")
	for index, domain := range request.Domains {
		builder.WriteString("DNS.")
		builder.WriteString(strconv.Itoa(index + 1))
		builder.WriteString(" = ")
		builder.WriteString(domain)
		builder.WriteByte('\n')
	}
	return builder.String()
}

type CommandError struct {
	ExitCode int
	Summary  string
	Cause    error
}

func (e *CommandError) Error() string {
	return fmt.Sprintf("OpenSSL 执行失败(exit=%d): %s", e.ExitCode, e.Summary)
}

func (e *CommandError) Unwrap() error { return e.Cause }

type limitedBuffer struct {
	buffer bytes.Buffer
	limit  int64
}

func (b *limitedBuffer) Write(value []byte) (int, error) {
	remaining := b.limit - int64(b.buffer.Len())
	if remaining <= 0 {
		return 0, errors.New("命令输出超过限制")
	}
	if int64(len(value)) > remaining {
		_, _ = b.buffer.Write(value[:remaining])
		return int(remaining), errors.New("命令输出超过限制")
	}
	return b.buffer.Write(value)
}

func (b *limitedBuffer) String() string { return b.buffer.String() }

func readLimited(filename string, limit int64) ([]byte, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	value, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(value)) > limit {
		return nil, errors.New("证书工具输出文件超过大小限制")
	}
	return value, nil
}

func sanitizeOutput(value, tempDir string) string {
	value = strings.ReplaceAll(value, tempDir, "<temp>")
	value = strings.TrimSpace(value)
	if len(value) > 4096 {
		value = value[:4096] + "…"
	}
	return value
}
