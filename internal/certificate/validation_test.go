package certificate

import (
	"errors"
	"testing"
)

func TestNormalizeDomainsDeduplicatesAndIncludesPrimary(t *testing.T) {
	primary, domains, err := NormalizeDomains("Example.COM", []string{"www.example.com", "example.com", "WWW.EXAMPLE.COM", "*.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if primary != "example.com" {
		t.Fatalf("primary = %s", primary)
	}
	want := []string{"example.com", "*.example.com", "www.example.com"}
	if len(domains) != len(want) {
		t.Fatalf("domains = %v", domains)
	}
	for index := range want {
		if domains[index] != want[index] {
			t.Fatalf("domains = %v", domains)
		}
	}
}

func TestValidateDomainRejectsInjectionAndInvalidWildcard(t *testing.T) {
	for _, value := range []string{"example.com\nDNS.2=evil.test", "../example.com", "foo.*.example.com", "*.com", "-bad.example.com", "example.com."} {
		if err := ValidateDomain(value, true); err == nil {
			t.Errorf("应拒绝 %q", value)
		}
	}
}

func TestValidateACMEDomainsRejectsWildcardCoveredDomain(t *testing.T) {
	tests := []struct {
		name            string
		primary         string
		domains         []string
		domain          string
		primaryConflict bool
	}{
		{name: "SAN 被覆盖", primary: "example.com", domains: []string{"example.com", "*.example.com", "www.example.com"}, domain: "www.example.com"},
		{name: "主域名被覆盖", primary: "www.example.com", domains: []string{"www.example.com", "*.example.com"}, domain: "www.example.com", primaryConflict: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := ValidateACMEDomains(test.primary, test.domains)
			var conflict *RedundantDomainError
			if !errors.As(err, &conflict) {
				t.Fatalf("error = %v", err)
			}
			if conflict.Domain != test.domain || conflict.Wildcard != "*.example.com" || conflict.Primary != test.primaryConflict {
				t.Fatalf("conflict = %+v", conflict)
			}
		})
	}
}

func TestValidateACMEDomainsAcceptsDistinctCoverage(t *testing.T) {
	for _, domains := range [][]string{
		{"example.com", "*.example.com"},
		{"example.com", "*.example.com", "a.b.example.com"},
	} {
		if err := ValidateACMEDomains("example.com", domains); err != nil {
			t.Fatalf("domains=%v error=%v", domains, err)
		}
	}
}

func TestSafeDirectoryFromDomain(t *testing.T) {
	if got := SafeDirectoryFromDomain("*.mail.example.com"); got != "mail-example-com" {
		t.Fatalf("safe directory = %s", got)
	}
}
