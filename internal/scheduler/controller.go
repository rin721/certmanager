package scheduler

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/robfig/cron/v3"
)

var ErrInvalidPolicy = errors.New("invalid renewal policy")

type Repository interface {
	RenewalPolicy(context.Context) (Policy, error)
	UpdateRenewalPolicy(context.Context, Policy) error
}

type Runner func(context.Context, Policy) error

type Status struct {
	Running    bool       `json:"running"`
	LastRunAt  *time.Time `json:"last_run_at,omitempty"`
	NextRunAt  *time.Time `json:"next_run_at,omitempty"`
	LastError  string     `json:"last_error,omitempty"`
	ActiveRuns int        `json:"active_runs"`
}

type Controller struct {
	store  Repository
	runner Runner
	logger *slog.Logger
	ctx    context.Context
	cancel context.CancelFunc

	mu        sync.RWMutex
	cron      *cron.Cron
	entryID   cron.EntryID
	policy    Policy
	lastRun   *time.Time
	lastError string
	runMu     sync.Mutex
	active    int
}

func NewController(parent context.Context, store Repository, runner Runner, logger *slog.Logger) *Controller {
	ctx, cancel := context.WithCancel(parent)
	return &Controller{store: store, runner: runner, logger: logger, ctx: ctx, cancel: cancel}
}

func (c *Controller) Start(ctx context.Context) error {
	policy, err := c.store.RenewalPolicy(ctx)
	if err != nil {
		return err
	}
	instance, entryID, err := c.build(policy)
	if err != nil {
		return err
	}
	instance.Start()
	c.mu.Lock()
	c.cron, c.entryID, c.policy = instance, entryID, policy
	c.mu.Unlock()
	return nil
}

func (c *Controller) Update(ctx context.Context, policy Policy) error {
	instance, entryID, err := c.build(policy)
	if err != nil {
		return err
	}
	if err := c.store.UpdateRenewalPolicy(ctx, policy); err != nil {
		return err
	}
	policy.UpdatedAt = time.Now().UTC()
	instance.Start()
	c.mu.Lock()
	old := c.cron
	c.cron, c.entryID, c.policy = instance, entryID, policy
	c.mu.Unlock()
	if old != nil {
		// Stop 会立即阻止旧调度产生新任务。已有任务由证书级互斥锁隔离，
		// 因而配置接口无需等待一个可能很长的续签扫描结束。
		old.Stop()
	}
	return nil
}

func (c *Controller) Policy() Policy {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.policy
}

func (c *Controller) RunNow() bool {
	if !c.runMu.TryLock() {
		return false
	}
	go c.executeLocked()
	return true
}

func (c *Controller) Status() Status {
	c.mu.RLock()
	defer c.mu.RUnlock()
	status := Status{Running: c.cron != nil, LastRunAt: c.lastRun, LastError: c.lastError, ActiveRuns: c.active}
	if c.cron != nil && c.entryID != 0 {
		next := c.cron.Entry(c.entryID).Next
		if !next.IsZero() {
			status.NextRunAt = &next
		}
	}
	return status
}

func (c *Controller) Stop(ctx context.Context) error {
	c.cancel()
	c.mu.Lock()
	instance := c.cron
	c.cron = nil
	c.mu.Unlock()
	if instance == nil {
		return nil
	}
	stopCtx := instance.Stop()
	select {
	case <-stopCtx.Done():
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (c *Controller) build(policy Policy) (*cron.Cron, cron.EntryID, error) {
	if err := Validate(policy); err != nil {
		return nil, 0, err
	}
	location, _ := time.LoadLocation(policy.Timezone)
	instance := cron.New(
		cron.WithLocation(location),
		cron.WithParser(cron.NewParser(cron.Minute|cron.Hour|cron.Dom|cron.Month|cron.Dow)),
		cron.WithChain(cron.Recover(cronLogger{logger: c.logger})),
	)
	var entryID cron.EntryID
	var err error
	if policy.Enabled {
		entryID, err = instance.AddFunc(policy.CronExpression, func() {
			if c.runMu.TryLock() {
				c.executeLocked()
			} else {
				c.logger.Warn("renewal scan skipped because previous scan is still running")
			}
		})
	}
	return instance, entryID, err
}

func (c *Controller) executeLocked() {
	defer c.runMu.Unlock()
	c.mu.Lock()
	c.active++
	policy := c.policy
	c.mu.Unlock()
	err := c.runner(c.ctx, policy)
	now := time.Now().UTC()
	c.mu.Lock()
	c.active--
	c.lastRun = &now
	if err != nil {
		c.lastError = err.Error()
	} else {
		c.lastError = ""
	}
	c.mu.Unlock()
}

func Validate(policy Policy) error {
	if policy.CronExpression == "" || policy.Timezone == "" || policy.MaxConcurrency < 1 || policy.MaxConcurrency > 16 || policy.RetryCount < 0 || policy.RetryCount > 10 || policy.RetryIntervalSeconds < 1 || policy.RetryIntervalSeconds > 86400 {
		return ErrInvalidPolicy
	}
	if _, err := time.LoadLocation(policy.Timezone); err != nil {
		return ErrInvalidPolicy
	}
	parser := cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow)
	if _, err := parser.Parse(policy.CronExpression); err != nil {
		return ErrInvalidPolicy
	}
	return nil
}

type cronLogger struct{ logger *slog.Logger }

func (l cronLogger) Info(msg string, keysAndValues ...any) { l.logger.Debug(msg, keysAndValues...) }
func (l cronLogger) Error(err error, msg string, keysAndValues ...any) {
	values := append(keysAndValues, "error", err)
	l.logger.Error(msg, values...)
}
