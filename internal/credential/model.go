package credential

import "time"

type Credential struct {
	ID              string            `json:"id"`
	Name            string            `json:"name"`
	Provider        string            `json:"provider"`
	ACMEDNSCode     string            `json:"acme_dns_code"`
	SourceMode      string            `json:"source_mode"`
	MaskedFields    []string          `json:"masked_fields"`
	EnvironmentRefs map[string]string `json:"environment_refs,omitempty"`
	CreatedAt       time.Time         `json:"created_at"`
	UpdatedAt       time.Time         `json:"updated_at"`
}

type CreateRequest struct {
	Name            string            `json:"name"`
	Provider        string            `json:"provider"`
	CustomACMECode  string            `json:"custom_acme_code,omitempty"`
	SourceMode      string            `json:"source_mode"`
	Values          map[string]string `json:"values,omitempty"`
	EnvironmentRefs map[string]string `json:"environment_refs,omitempty"`
}

type ProcessValues struct {
	ACMEDNSCode string
	Environment map[string]string
}
