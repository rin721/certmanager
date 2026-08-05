// Package certificate 定义项目拥有的证书领域模型。
package certificate

import "time"

type Mode string

const (
	ModeACME       Mode = "acme"
	ModeSelfSigned Mode = "self_signed"
)

type Status string

const (
	StatusPending  Status = "pending"
	StatusIssuing  Status = "issuing"
	StatusActive   Status = "active"
	StatusExpiring Status = "expiring"
	StatusExpired  Status = "expired"
	StatusRenewing Status = "renewing"
	StatusFailed   Status = "failed"
	StatusDisabled Status = "disabled"
	StatusRevoked  Status = "revoked"
)

type Certificate struct {
	ID                  string     `json:"id"`
	Name                string     `json:"name"`
	Mode                Mode       `json:"mode"`
	PrimaryDomain       string     `json:"primary_domain"`
	Domains             []string   `json:"domains"`
	KeyType             string     `json:"key_type"`
	Status              Status     `json:"status"`
	OutputDirectory     string     `json:"output_directory"`
	Issuer              string     `json:"issuer"`
	SerialNumber        string     `json:"serial_number"`
	NotBefore           *time.Time `json:"not_before,omitempty"`
	NotAfter            *time.Time `json:"not_after,omitempty"`
	FingerprintSHA256   string     `json:"fingerprint_sha256"`
	AutoRenewEnabled    bool       `json:"auto_renew_enabled"`
	RenewBeforeDays     int        `json:"renew_before_days"`
	ChallengeType       string     `json:"challenge_type,omitempty"`
	DNSProvider         string     `json:"dns_provider,omitempty"`
	DNSCredentialID     string     `json:"dns_credential_id,omitempty"`
	CADirectoryURL      string     `json:"ca_directory_url,omitempty"`
	ACMEEmail           string     `json:"acme_email,omitempty"`
	SelfSignedValidDays int        `json:"self_signed_valid_days,omitempty"`
	CreateRenewedMarker bool       `json:"create_renewed_marker"`
	CreatedAt           time.Time  `json:"created_at"`
	UpdatedAt           time.Time  `json:"updated_at"`
	LastIssuedAt        *time.Time `json:"last_issued_at,omitempty"`
	LastRenewedAt       *time.Time `json:"last_renewed_at,omitempty"`
	NextCheckAt         *time.Time `json:"next_check_at,omitempty"`
	LastError           string     `json:"last_error,omitempty"`
}
