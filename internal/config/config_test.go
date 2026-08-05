package config

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestLoadRejectsMissingAdminPassword(t *testing.T) {
	clearSecrets(t)
	t.Setenv("SESSION_SECRET", "0123456789abcdef0123456789abcdef")
	_, err := Load()
	if err == nil {
		t.Fatal("未配置管理员密码时必须拒绝启动")
	}
}

func TestTrustedProxyRequiresCIDRAndRejectsUntrustedPeer(t *testing.T) {
	clearSecrets(t)
	t.Setenv("ADMIN_PASSWORD", "plain-secret")
	t.Setenv("SESSION_SECRET", "0123456789abcdef0123456789abcdef")
	t.Setenv("TRUST_PROXY", "true")
	if _, err := Load(); err == nil {
		t.Fatal("开启代理信任时必须要求显式 CIDR")
	}
	t.Setenv("TRUSTED_PROXY_CIDRS", "127.0.0.1/32,10.20.0.0/16")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.TrustsProxy("10.20.3.4:54321") || cfg.TrustsProxy("10.21.3.4:54321") {
		t.Fatal("只应信任显式配置的代理网段")
	}
}

func TestLoadUsesPasswordHashFileBeforeOtherSources(t *testing.T) {
	clearSecrets(t)
	directory := t.TempDir()
	hash, err := bcrypt.GenerateFromPassword([]byte("from-file"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	filename := filepath.Join(directory, "password.hash")
	if err := os.WriteFile(filename, append(hash, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ADMIN_PASSWORD_HASH_FILE", filename)
	t.Setenv("ADMIN_PASSWORD", "lower-priority")
	t.Setenv("SESSION_SECRET", "0123456789abcdef0123456789abcdef")

	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.PlaintextPassword {
		t.Fatal("哈希文件不应被标记为明文密码")
	}
	if err := bcrypt.CompareHashAndPassword(cfg.AdminPasswordHash, []byte("from-file")); err != nil {
		t.Fatal("未使用最高优先级的哈希文件")
	}
}

func TestLoadHashesPlaintextPassword(t *testing.T) {
	clearSecrets(t)
	t.Setenv("ADMIN_PASSWORD", "plain-secret")
	t.Setenv("SESSION_SECRET", "0123456789abcdef0123456789abcdef")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.PlaintextPassword {
		t.Fatal("应记录明文配置来源以便产生生产安全警告")
	}
	if err := bcrypt.CompareHashAndPassword(cfg.AdminPasswordHash, []byte("plain-secret")); err != nil {
		t.Fatal("内存中应仅保留启动时生成的 bcrypt 哈希")
	}
}

func clearSecrets(t *testing.T) {
	t.Helper()
	for _, name := range []string{
		"ADMIN_PASSWORD_HASH_FILE", "ADMIN_PASSWORD_HASH", "ADMIN_PASSWORD_FILE", "ADMIN_PASSWORD",
		"SESSION_SECRET_FILE", "SESSION_SECRET", "SESSION_COOKIE_SECURE",
		"TRUST_PROXY", "TRUSTED_PROXY_CIDRS",
	} {
		t.Setenv(name, "")
	}
	t.Setenv("APP_ENV", "test")
	t.Setenv("ENABLE_ACME", "false")
}
