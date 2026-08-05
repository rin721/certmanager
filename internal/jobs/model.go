// Package jobs 定义外部证书操作的可审计任务记录。
package jobs

import "time"

type Run struct {
	ID              string     `json:"id"`
	CertificateID   string     `json:"certificate_id,omitempty"`
	JobType         string     `json:"job_type"`
	Status          string     `json:"status"`
	StartedAt       time.Time  `json:"started_at"`
	FinishedAt      *time.Time `json:"finished_at,omitempty"`
	ExitCode        *int       `json:"exit_code,omitempty"`
	SanitizedOutput string     `json:"sanitized_output,omitempty"`
	ErrorMessage    string     `json:"error_message,omitempty"`
	Attempt         int        `json:"attempt"`
}

type Query struct {
	CertificateID string
	Status        string
	JobType       string
	Since         *time.Time
	Limit         int
}
