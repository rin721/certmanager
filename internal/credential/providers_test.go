package credential

import (
	"strings"
	"testing"
)

func TestRegistryContainsOfficialACMEShFields(t *testing.T) {
	registry := NewRegistry()
	tests := map[string][]string{
		"cloudflare":  {"CF_Token", "CF_Zone_ID", "CF_Account_ID"},
		"alidns":      {"Ali_Key", "Ali_Secret"},
		"dnspod":      {"DP_Id", "DP_Key"},
		"route53":     {"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"},
		"huaweicloud": {"HUAWEICLOUD_Username", "HUAWEICLOUD_Password", "HUAWEICLOUD_DomainName", "HUAWEICLOUD_Region"},
	}
	for code, names := range tests {
		provider, ok := registry.Get(code)
		if !ok {
			t.Fatalf("缺少 Provider %s", code)
		}
		found := make(map[string]bool)
		for _, field := range provider.Fields {
			found[field.Name] = true
		}
		for _, name := range names {
			if !found[name] {
				t.Errorf("Provider %s 缺少 %s", code, name)
			}
		}
	}
	cloudflare, ok := registry.Get("cloudflare")
	if !ok || !strings.Contains(cloudflare.DocumentationHint, "Zone:Zone:Read") || !strings.Contains(cloudflare.DocumentationHint, "Zone:DNS:Edit") {
		t.Fatalf("Cloudflare 权限提示不完整: %+v", cloudflare)
	}
}

func TestValidateEnvironmentNameRejectsDangerousOverrides(t *testing.T) {
	for _, name := range []string{"PATH", "HOME", "LD_PRELOAD", "APP_ENCRYPTION_KEY", "ADMIN_PASSWORD", "SESSION_SECRET", "lowercase", "A=B"} {
		if err := ValidateEnvironmentName(name); err == nil {
			t.Errorf("应拒绝 %q", name)
		}
	}
	for _, name := range []string{"AWS_ACCESS_KEY_ID", "CUSTOM_API_TOKEN"} {
		if err := ValidateEnvironmentName(name); err != nil {
			t.Errorf("应允许 %q: %v", name, err)
		}
	}
	if err := ValidateProcessEnvironmentName("CF_Token"); err != nil {
		t.Fatalf("内置 Provider 的官方混合大小写变量名应允许: %v", err)
	}
}

func TestCipherRoundTripAndAuthentication(t *testing.T) {
	cipher, err := NewCipher([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	value, err := cipher.Encrypt(map[string]string{"CF_Token": "secret-token"})
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := cipher.Decrypt(value)
	if err != nil || decoded["CF_Token"] != "secret-token" {
		t.Fatalf("decoded=%v err=%v", decoded, err)
	}
	value[len(value)-1] ^= 1
	if _, err := cipher.Decrypt(value); err == nil {
		t.Fatal("篡改密文必须认证失败")
	}
}
