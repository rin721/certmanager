package selfsigned

import (
	"strings"
	"testing"
)

func TestBuildArgumentsUsesOnlyWhitelistedKeyTypes(t *testing.T) {
	arguments, err := buildArguments(Request{KeyType: "ec-256", ValidDays: 90})
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(arguments, " ")
	if !strings.Contains(joined, "ec_paramgen_curve:P-256") || !strings.Contains(joined, "-days 90") {
		t.Fatalf("arguments = %v", arguments)
	}
	if _, err := buildArguments(Request{KeyType: "rsa:2048; touch /tmp/pwn", ValidDays: 90}); err == nil {
		t.Fatal("任意密钥参数必须被拒绝")
	}
}

func TestBuildConfigContainsValidatedSANEntries(t *testing.T) {
	config := buildConfig(Request{PrimaryDomain: "example.com", Domains: []string{"example.com", "www.example.com"}})
	for _, value := range []string{"CN = example.com", "DNS.1 = example.com", "DNS.2 = www.example.com"} {
		if !strings.Contains(config, value) {
			t.Fatalf("配置缺少 %q: %s", value, config)
		}
	}
}

func TestLimitedBufferRejectsOversizedOutput(t *testing.T) {
	buffer := &limitedBuffer{limit: 4}
	if _, err := buffer.Write([]byte("12345")); err == nil {
		t.Fatal("超限输出必须返回错误")
	}
	if buffer.String() != "1234" {
		t.Fatalf("buffer = %q", buffer.String())
	}
}
