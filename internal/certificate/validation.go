package certificate

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

// RedundantDomainError 表示 ACME 域名集合包含已被通配符覆盖的普通域名。
type RedundantDomainError struct {
	Domain   string
	Wildcard string
	Primary  bool
}

func (e *RedundantDomainError) Error() string {
	if e.Primary {
		return fmt.Sprintf("主域名 %q 已被通配符 %q 覆盖，请将主域名改为基础域名或删除通配符", e.Domain, e.Wildcard)
	}
	return fmt.Sprintf("SAN 域名 %q 已被通配符 %q 覆盖，请删除其中一个", e.Domain, e.Wildcard)
}

func NormalizeDomains(primary string, sans []string) (string, []string, error) {
	primary = strings.ToLower(strings.TrimSpace(primary))
	if err := ValidateDomain(primary, false); err != nil {
		return "", nil, fmt.Errorf("主域名: %w", err)
	}
	seen := map[string]struct{}{primary: {}}
	domains := []string{primary}
	for _, value := range sans {
		domain := strings.ToLower(strings.TrimSpace(value))
		if domain == "" {
			continue
		}
		if err := ValidateDomain(domain, true); err != nil {
			return "", nil, fmt.Errorf("SAN %q: %w", value, err)
		}
		if _, exists := seen[domain]; exists {
			continue
		}
		seen[domain] = struct{}{}
		domains = append(domains, domain)
	}
	sort.Strings(domains[1:])
	return primary, domains, nil
}

// ValidateACMEDomains 拒绝 ACME CA 不接受的通配符冗余域名组合。
func ValidateACMEDomains(primary string, domains []string) error {
	wildcards := make([]string, 0)
	for _, domain := range domains {
		if strings.HasPrefix(domain, "*.") {
			wildcards = append(wildcards, domain)
		}
	}
	sort.Strings(wildcards)
	for _, domain := range domains {
		if strings.HasPrefix(domain, "*.") {
			continue
		}
		for _, wildcard := range wildcards {
			if wildcardCoversDomain(wildcard, domain) {
				return &RedundantDomainError{Domain: domain, Wildcard: wildcard, Primary: domain == primary}
			}
		}
	}
	return nil
}

func wildcardCoversDomain(wildcard, domain string) bool {
	baseDomain := strings.TrimPrefix(wildcard, "*.")
	suffix := "." + baseDomain
	if !strings.HasSuffix(domain, suffix) {
		return false
	}
	leftmostLabel := strings.TrimSuffix(domain, suffix)
	return leftmostLabel != "" && !strings.Contains(leftmostLabel, ".")
}

func ValidateDomain(domain string, allowWildcard bool) error {
	if domain == "" || len(domain) > 253 {
		return errors.New("域名长度无效")
	}
	if domain != strings.ToLower(domain) || strings.TrimSpace(domain) != domain || strings.HasSuffix(domain, ".") {
		return errors.New("域名必须是无尾点的小写 ASCII 名称")
	}
	if strings.HasPrefix(domain, "*.") {
		if !allowWildcard {
			return errors.New("主域名不能使用通配符")
		}
		domain = strings.TrimPrefix(domain, "*.")
		if strings.Count(domain, ".") < 1 {
			return errors.New("通配符域名至少需要两级基础域名")
		}
	}
	if strings.Contains(domain, "*") {
		return errors.New("通配符只能出现在最左侧标签")
	}
	labels := strings.Split(domain, ".")
	if len(labels) < 2 {
		return errors.New("域名至少需要两个标签")
	}
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return errors.New("域名标签长度或连字符位置无效")
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
				return errors.New("域名只能包含 ASCII 字母、数字、连字符和点")
			}
		}
	}
	return nil
}

func SafeDirectoryFromDomain(domain string) string {
	value := strings.TrimPrefix(strings.ToLower(domain), "*.")
	value = strings.ReplaceAll(value, ".", "-")
	value = strings.Trim(value, "-")
	if len(value) > 63 {
		value = strings.TrimRight(value[:63], "-")
	}
	return value
}
