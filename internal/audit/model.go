// Package audit 定义不含敏感值的管理员操作审计记录。
package audit

import "time"

type Event struct {
	ID            string         `json:"id"`
	CertificateID string         `json:"certificate_id,omitempty"`
	EventType     string         `json:"event_type"`
	Actor         string         `json:"actor"`
	ClientIP      string         `json:"client_ip,omitempty"`
	Result        string         `json:"result"`
	Detail        map[string]any `json:"detail,omitempty"`
	CreatedAt     time.Time      `json:"created_at"`
}

type Query struct {
	CertificateID string
	EventType     string
	Since         *time.Time
	Limit         int
}
