package certificate

import (
	"errors"
	"fmt"

	"github.com/rin721/certmate/internal/certificate/acmesh"
)

// DNSZoneUnavailableError 表示 DNS Provider 无法定位或访问证书域名所属的 Zone。
type DNSZoneUnavailableError struct {
	Domain string
	Cause  error
}

func (e *DNSZoneUnavailableError) Error() string {
	return fmt.Sprintf("Cloudflare 无法访问域名 %q 的 Zone；请确认 Token 有效，具备 Zone:Zone:Read 和 Zone:DNS:Edit 权限，资源范围包含该 Zone，且 Token IP 限制允许当前服务器", e.Domain)
}

func (e *DNSZoneUnavailableError) Unwrap() error { return e.Cause }

func normalizeACMEError(err error, primaryDomain string) error {
	var commandErr *acmesh.CommandError
	if errors.As(err, &commandErr) && commandErr.Kind == acmesh.FailureDNSZoneUnavailable {
		return &DNSZoneUnavailableError{Domain: primaryDomain, Cause: err}
	}
	return err
}
