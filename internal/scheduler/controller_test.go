package scheduler

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"
)

type policyStore struct {
	mu      sync.Mutex
	policy  Policy
	updates int
}

func (s *policyStore) RenewalPolicy(context.Context) (Policy, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.policy, nil
}

func (s *policyStore) UpdateRenewalPolicy(_ context.Context, policy Policy) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.policy = policy
	s.updates++
	return nil
}

func TestControllerHotUpdateAndInvalidPolicyKeepsOldSchedule(t *testing.T) {
	initial := Policy{Enabled: true, CronExpression: "0 3 * * *", Timezone: "Asia/Shanghai", MaxConcurrency: 2, RetryCount: 1, RetryIntervalSeconds: 10}
	store := &policyStore{policy: initial}
	controller := NewController(context.Background(), store, func(context.Context, Policy) error { return nil }, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := controller.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = controller.Stop(context.Background()) })
	before := controller.Status().NextRunAt
	if before == nil {
		t.Fatal("启用策略必须存在下次运行时间")
	}
	invalid := initial
	invalid.CronExpression = "not a cron"
	if err := controller.Update(context.Background(), invalid); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatalf("invalid update err=%v", err)
	}
	if store.updates != 0 || controller.Policy().CronExpression != initial.CronExpression {
		t.Fatal("无效策略不得落库或替换旧策略")
	}
	updated := initial
	updated.CronExpression = "15 4 * * *"
	updated.MaxConcurrency = 3
	if err := controller.Update(context.Background(), updated); err != nil {
		t.Fatal(err)
	}
	if store.updates != 1 || controller.Policy().CronExpression != updated.CronExpression {
		t.Fatal("有效策略未热更新")
	}
	after := controller.Status().NextRunAt
	if after == nil || after.Equal(*before) {
		t.Fatalf("热更新后 NextRun 未变化: before=%v after=%v", before, after)
	}
}

func TestRunNowRejectsOverlappingScan(t *testing.T) {
	policy := Policy{Enabled: false, CronExpression: "0 3 * * *", Timezone: "UTC", MaxConcurrency: 1, RetryCount: 0, RetryIntervalSeconds: 1}
	store := &policyStore{policy: policy}
	started, release := make(chan struct{}), make(chan struct{})
	controller := NewController(context.Background(), store, func(context.Context, Policy) error {
		close(started)
		<-release
		return nil
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := controller.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !controller.RunNow() {
		t.Fatal("首次 RunNow 应启动")
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("扫描未启动")
	}
	if controller.RunNow() {
		t.Fatal("重叠 RunNow 必须拒绝")
	}
	close(release)
	deadline := time.Now().Add(time.Second)
	for controller.Status().ActiveRuns != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if controller.Status().ActiveRuns != 0 {
		t.Fatal("扫描未结束")
	}
	if err := controller.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
}
