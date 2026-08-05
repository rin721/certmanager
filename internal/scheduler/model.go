// Package scheduler 管理可热更新的证书检查策略。
package scheduler

import "time"

type Policy struct {
	Enabled              bool      `json:"enabled"`
	CronExpression       string    `json:"cron_expression"`
	Timezone             string    `json:"timezone"`
	MaxConcurrency       int       `json:"max_concurrency"`
	RetryCount           int       `json:"retry_count"`
	RetryIntervalSeconds int       `json:"retry_interval_seconds"`
	UpdatedAt            time.Time `json:"updated_at"`
}
