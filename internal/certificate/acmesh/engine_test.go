package acmesh

import (
	"strings"
	"testing"
)

func TestIssueArgumentsDNSUsesArraysAndNoSecrets(t *testing.T) {
	cli := NewCLI("acme.sh", "/data/acme", "/data/challenges", "/data/temp", 0)
	arguments, err := cli.issueArguments(IssueRequest{
		PrimaryDomain: "example.com", Domains: []string{"example.com", "*.example.com"}, KeyType: "ec-256",
		ChallengeType: "dns-01", DNSProvider: "dns_cf", DNSVariables: map[string]string{"CF_Token": "top-secret"},
		CADirectory: "letsencrypt", Email: "admin@example.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(arguments, " ")
	for _, expected := range []string{"--issue", "--server letsencrypt", "-d example.com", "-d *.example.com", "--dns dns_cf", "--keylength ec-256"} {
		if !strings.Contains(joined, expected) {
			t.Errorf("arguments 缺少 %q: %v", expected, arguments)
		}
	}
	if strings.Contains(joined, "top-secret") || strings.Contains(joined, "--force") {
		t.Fatal("凭据和 --force 不得进入普通签发参数")
	}
}

func TestHTTP01RejectsWildcard(t *testing.T) {
	cli := NewCLI("acme.sh", "/data/acme", "/data/challenges", "/data/temp", 0)
	_, err := cli.issueArguments(IssueRequest{
		PrimaryDomain: "example.com", Domains: []string{"example.com", "*.example.com"}, KeyType: "ec-256",
		ChallengeType: "http-01", CADirectory: "letsencrypt_test", Email: "admin@example.com",
	})
	if err == nil {
		t.Fatal("HTTP-01 必须拒绝通配符")
	}
}

func TestRenewForceIsExplicit(t *testing.T) {
	cli := NewCLI("acme.sh", "/data/acme", "/data/challenges", "/data/temp", 0)
	normal, err := cli.renewArguments(RenewRequest{PrimaryDomain: "example.com", KeyType: "ec-256", CADirectory: "letsencrypt"})
	if err != nil {
		t.Fatal(err)
	}
	forced, err := cli.renewArguments(RenewRequest{PrimaryDomain: "example.com", KeyType: "ec-256", Force: true, CADirectory: "letsencrypt"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.Join(normal, " "), "--force") || !strings.Contains(strings.Join(forced, " "), "--force") {
		t.Fatal("--force 只能由显式 Force=true 添加")
	}
}

func TestCustomCADirectoryIsPassedToRenew(t *testing.T) {
	cli := NewCLI("acme.sh", "/data/acme", "/data/challenges", "/data/temp", 0)
	arguments, err := cli.renewArguments(RenewRequest{PrimaryDomain: "example.com", KeyType: "ec-256", CADirectory: "https://acme.example.com/directory"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(arguments, " "), "--server https://acme.example.com/directory") {
		t.Fatalf("自定义 CA 未透传: %v", arguments)
	}
}

func TestRedactOutputRemovesCredentialValues(t *testing.T) {
	result := redactOutput("request token=top-secret and top", map[string]string{"TOKEN": "top-secret", "SHORT": "top"})
	if strings.Contains(result, "top-secret") || strings.Contains(result, " top") {
		t.Fatalf("脱敏失败: %s", result)
	}
}

func TestRedactOutputRemovesDNSChallengeValue(t *testing.T) {
	result := redactOutput("Adding TXT value: challenge-value for domain: _acme-challenge.example.com", nil)
	if strings.Contains(result, "challenge-value") {
		t.Fatalf("DNS 挑战值未脱敏: %s", result)
	}
	if !strings.Contains(result, "Adding TXT value: [REDACTED] for domain: _acme-challenge.example.com") {
		t.Fatalf("脱敏后应保留安全诊断上下文: %s", result)
	}
}

func TestClassifyCloudflareZoneFailure(t *testing.T) {
	output := "invalid domain\nError adding TXT record to domain: _acme-challenge.example.com"
	if kind := classifyDNSFailure("dns_cf", output); kind != FailureDNSZoneUnavailable {
		t.Fatalf("Cloudflare Zone 查询失败分类错误: %q", kind)
	}
	for _, provider := range []string{"dns_ali", "dns_dp", ""} {
		if kind := classifyDNSFailure(provider, output); kind != "" {
			t.Fatalf("Provider %q 不应被误判: %q", provider, kind)
		}
	}
	if kind := classifyDNSFailure("dns_cf", "invalid domain"); kind != "" {
		t.Fatalf("缺少 TXT 写入上下文时不应误判: %q", kind)
	}
}

func TestRejectsDomainAndCAInjection(t *testing.T) {
	for _, domain := range []string{"example.com\n--force", "../example.com", "foo.-bad.com"} {
		if err := validateDomain(domain); err == nil {
			t.Errorf("应拒绝域名 %q", domain)
		}
	}
	for _, ca := range []string{"http://ca.example/directory", "https://user:pass@ca.example/directory", "https://ca.example/#fragment"} {
		if _, err := validateCA(ca); err == nil {
			t.Errorf("应拒绝 CA %q", ca)
		}
	}
}
