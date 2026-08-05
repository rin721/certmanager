// Package config 负责读取不可动态修改的启动配置。
package config

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/rin721/certmate/internal/project"
	"golang.org/x/crypto/bcrypt"
)

type Config struct {
	BuildVersion        string
	AppName             string
	Environment         string
	ListenAddr          string
	Timezone            string
	DataDir             string
	CertOutputDir       string
	ACMEHome            string
	ACMEChallengeDir    string
	LogLevel            string
	TrustProxy          bool
	trustedProxyCIDRs   []netip.Prefix
	EnableACME          bool
	EnableSelfSigned    bool
	DefaultCA           string
	DefaultACMEEmail    string
	DefaultKeyType      string
	ShutdownTimeout     time.Duration
	AdminUsername       string
	AdminPasswordHash   []byte
	PlaintextPassword   bool
	SessionSecret       []byte
	SessionTTL          time.Duration
	SessionCookieSecure bool
	OpenSSLBinary       string
	ACMEShBinary        string
	CommandTimeout      time.Duration
	AppEncryptionKey    []byte
}

func Load() (Config, error) {
	cfg := Config{
		AppName:          envOr("APP_NAME", project.DefaultName),
		Environment:      envOr("APP_ENV", "production"),
		ListenAddr:       envOr("LISTEN_ADDR", ":8080"),
		Timezone:         envOr("TZ", "Asia/Shanghai"),
		DataDir:          envOr("DATA_DIR", "/data"),
		CertOutputDir:    envOr("CERT_OUTPUT_DIR", "/certs"),
		ACMEHome:         envOr("ACME_HOME", "/data/acme"),
		ACMEChallengeDir: envOr("ACME_CHALLENGE_DIR", "/data/challenges"),
		LogLevel:         envOr("LOG_LEVEL", "info"),
		DefaultCA:        envOr("DEFAULT_CA", "letsencrypt"),
		DefaultACMEEmail: strings.TrimSpace(os.Getenv("DEFAULT_ACME_EMAIL")),
		DefaultKeyType:   envOr("DEFAULT_KEY_TYPE", "ec-256"),
		ShutdownTimeout:  15 * time.Second,
		AdminUsername:    envOr("ADMIN_USERNAME", "admin"),
		SessionTTL:       12 * time.Hour,
		OpenSSLBinary:    envOr("OPENSSL_BINARY", "openssl"),
		ACMEShBinary:     envOr("ACME_SH_BINARY", "acme.sh"),
		CommandTimeout:   90 * time.Second,
	}

	var err error
	if cfg.TrustProxy, err = boolEnv("TRUST_PROXY", false); err != nil {
		return Config{}, err
	}
	if cfg.trustedProxyCIDRs, err = parseTrustedProxyCIDRs(os.Getenv("TRUSTED_PROXY_CIDRS")); err != nil {
		return Config{}, err
	}
	if cfg.EnableACME, err = boolEnv("ENABLE_ACME", true); err != nil {
		return Config{}, err
	}
	if cfg.EnableSelfSigned, err = boolEnv("ENABLE_SELF_SIGNED", true); err != nil {
		return Config{}, err
	}
	if cfg.SessionCookieSecure, err = boolEnv("SESSION_COOKIE_SECURE", cfg.Environment == "production"); err != nil {
		return Config{}, err
	}
	if cfg.AdminPasswordHash, cfg.PlaintextPassword, err = loadAdminPasswordHash(); err != nil {
		return Config{}, err
	}
	if cfg.SessionSecret, err = loadSecret("SESSION_SECRET_FILE", "SESSION_SECRET"); err != nil {
		return Config{}, err
	}
	if cfg.EnableACME {
		if cfg.AppEncryptionKey, err = loadSecret("APP_ENCRYPTION_KEY_FILE", "APP_ENCRYPTION_KEY"); err != nil {
			return Config{}, err
		}
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (c Config) Validate() error {
	if strings.TrimSpace(c.AppName) == "" {
		return errors.New("APP_NAME 不能为空")
	}
	if c.ListenAddr == "" {
		return errors.New("LISTEN_ADDR 不能为空")
	}
	if !absolutePath(c.DataDir) || !absolutePath(c.CertOutputDir) || !absolutePath(c.ACMEHome) || !absolutePath(c.ACMEChallengeDir) {
		return errors.New("DATA_DIR、CERT_OUTPUT_DIR、ACME_HOME 和 ACME_CHALLENGE_DIR 必须是容器内绝对路径")
	}
	if _, err := time.LoadLocation(c.Timezone); err != nil {
		return fmt.Errorf("TZ 无效: %w", err)
	}
	if strings.TrimSpace(c.AdminUsername) == "" {
		return errors.New("ADMIN_USERNAME 不能为空")
	}
	if c.TrustProxy && len(c.trustedProxyCIDRs) == 0 {
		return errors.New("TRUST_PROXY=true 时必须配置 TRUSTED_PROXY_CIDRS")
	}
	if len(c.AdminPasswordHash) == 0 {
		return errors.New("必须配置管理员密码或密码哈希")
	}
	if len(c.SessionSecret) < 32 {
		return errors.New("SESSION_SECRET 至少需要 32 字节")
	}
	if c.EnableACME && len(c.AppEncryptionKey) < 32 {
		return errors.New("启用 ACME 时 APP_ENCRYPTION_KEY 至少需要 32 字节")
	}
	return nil
}

func (c Config) TrustsProxy(remoteAddress string) bool {
	if !c.TrustProxy {
		return false
	}
	host, _, err := net.SplitHostPort(remoteAddress)
	if err != nil {
		host = strings.Trim(remoteAddress, "[]")
	}
	address, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	for _, prefix := range c.trustedProxyCIDRs {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

func parseTrustedProxyCIDRs(raw string) ([]netip.Prefix, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	values := make([]netip.Prefix, 0)
	for _, item := range strings.Split(raw, ",") {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(item))
		if err != nil {
			return nil, fmt.Errorf("TRUSTED_PROXY_CIDRS 包含无效 CIDR: %w", err)
		}
		values = append(values, prefix.Masked())
	}
	return values, nil
}

func absolutePath(value string) bool {
	return filepath.IsAbs(value) || strings.HasPrefix(value, "/")
}

func loadAdminPasswordHash() ([]byte, bool, error) {
	type source struct {
		fileEnv   string
		valueEnv  string
		plaintext bool
	}
	for _, candidate := range []source{
		{fileEnv: "ADMIN_PASSWORD_HASH_FILE"},
		{valueEnv: "ADMIN_PASSWORD_HASH"},
		{fileEnv: "ADMIN_PASSWORD_FILE", plaintext: true},
		{valueEnv: "ADMIN_PASSWORD", plaintext: true},
	} {
		var value []byte
		var err error
		switch {
		case candidate.fileEnv != "" && strings.TrimSpace(os.Getenv(candidate.fileEnv)) != "":
			value, err = readSecretFile(candidate.fileEnv)
		case candidate.valueEnv != "" && os.Getenv(candidate.valueEnv) != "":
			value = []byte(os.Getenv(candidate.valueEnv))
		default:
			continue
		}
		if err != nil {
			return nil, false, err
		}
		if len(value) == 0 {
			return nil, false, fmt.Errorf("%s 配置为空", firstNonEmpty(candidate.fileEnv, candidate.valueEnv))
		}
		if candidate.plaintext {
			hash, hashErr := bcrypt.GenerateFromPassword(value, bcrypt.DefaultCost)
			if hashErr != nil {
				return nil, false, fmt.Errorf("管理员密码哈希失败: %w", hashErr)
			}
			return hash, true, nil
		}
		if _, costErr := bcrypt.Cost(value); costErr != nil {
			return nil, false, errors.New("管理员密码哈希不是有效的 bcrypt 格式")
		}
		return append([]byte(nil), value...), false, nil
	}
	return nil, false, errors.New("必须按优先级配置 ADMIN_PASSWORD_HASH_FILE、ADMIN_PASSWORD_HASH、ADMIN_PASSWORD_FILE 或 ADMIN_PASSWORD")
}

func loadSecret(fileEnv, valueEnv string) ([]byte, error) {
	if strings.TrimSpace(os.Getenv(fileEnv)) != "" {
		return readSecretFile(fileEnv)
	}
	value := os.Getenv(valueEnv)
	if value == "" {
		return nil, fmt.Errorf("必须配置 %s 或 %s", fileEnv, valueEnv)
	}
	return []byte(value), nil
}

func readSecretFile(envName string) ([]byte, error) {
	filename := strings.TrimSpace(os.Getenv(envName))
	value, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("读取 %s 指向的文件失败: %w", envName, err)
	}
	return []byte(strings.TrimRight(string(value), "\r\n")), nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return "secret"
}

func envOr(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

func boolEnv(name string, fallback bool) (bool, error) {
	value := strings.TrimSpace(strings.ToLower(os.Getenv(name)))
	if value == "" {
		return fallback, nil
	}
	switch value {
	case "1", "true", "yes", "on":
		return true, nil
	case "0", "false", "no", "off":
		return false, nil
	default:
		return false, fmt.Errorf("%s 必须是布尔值", name)
	}
}
