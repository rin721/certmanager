package auth

import (
	"testing"
	"time"
)

func TestLoginLimiterLocksAndRecovers(t *testing.T) {
	limiter := NewLoginLimiter()
	now := time.Date(2026, 8, 5, 12, 0, 0, 0, time.UTC)
	limiter.now = func() time.Time { return now }

	for range limiter.maxFailures {
		if !limiter.Allow("client") {
			t.Fatal("达到阈值前不应锁定")
		}
		limiter.Failure("client")
	}
	if limiter.Allow("client") {
		t.Fatal("达到失败阈值后应锁定")
	}
	now = now.Add(limiter.lockout + time.Second)
	if !limiter.Allow("client") {
		t.Fatal("锁定期结束后应允许重试")
	}
}

func TestLoginLimiterSuccessClearsFailures(t *testing.T) {
	limiter := NewLoginLimiter()
	for range limiter.maxFailures - 1 {
		limiter.Failure("client")
	}
	limiter.Success("client")
	if !limiter.Allow("client") {
		t.Fatal("成功登录后应清除失败计数")
	}
}

func TestLoginLimiterBoundsStateMemory(t *testing.T) {
	limiter := NewLoginLimiter()
	limiter.maxStates = 8
	for index := range 100 {
		limiter.Failure(string(rune('a' + index)))
	}
	if len(limiter.states) > limiter.maxStates {
		t.Fatalf("限流状态数量失控: %d", len(limiter.states))
	}
}
