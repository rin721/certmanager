package certificate

import "testing"

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

func TestSafeDirectoryFromDomain(t *testing.T) {
	if got := SafeDirectoryFromDomain("*.mail.example.com"); got != "mail-example-com" {
		t.Fatalf("safe directory = %s", got)
	}
}
