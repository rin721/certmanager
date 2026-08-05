package certificate

import (
	"errors"
	"testing"

	"github.com/rin721/certmate/internal/certificate/acmesh"
)

func TestNormalizeACMEErrorPreservesCause(t *testing.T) {
	cause := errors.New("exit status 1")
	commandErr := &acmesh.CommandError{Operation: "issue", ExitCode: 1, Kind: acmesh.FailureDNSZoneUnavailable, Cause: cause}
	result := normalizeACMEError(commandErr, "example.com")
	var zoneError *DNSZoneUnavailableError
	if !errors.As(result, &zoneError) {
		t.Fatalf("未转换为 DNS Zone 错误: %T %v", result, result)
	}
	if !errors.Is(result, cause) {
		t.Fatal("转换后必须保留原始错误链")
	}
}
