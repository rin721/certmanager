package auth

import (
	"sync"
	"time"
)

type attemptState struct {
	failures    []time.Time
	lockedUntil time.Time
}

type LoginLimiter struct {
	mu          sync.Mutex
	states      map[string]*attemptState
	maxFailures int
	window      time.Duration
	lockout     time.Duration
	now         func() time.Time
	maxStates   int
}

func NewLoginLimiter() *LoginLimiter {
	return &LoginLimiter{
		states:      make(map[string]*attemptState),
		maxFailures: 5,
		window:      15 * time.Minute,
		lockout:     5 * time.Minute,
		now:         time.Now,
		maxStates:   4096,
	}
}

func (l *LoginLimiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	state := l.states[key]
	if state == nil {
		return true
	}
	now := l.now()
	if now.Before(state.lockedUntil) {
		return false
	}
	state.failures = recent(state.failures, now.Add(-l.window))
	if len(state.failures) == 0 {
		delete(l.states, key)
	}
	return true
}

func (l *LoginLimiter) Failure(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	state := l.states[key]
	if state == nil {
		l.prune(now)
		if len(l.states) >= l.maxStates {
			return
		}
		state = &attemptState{}
		l.states[key] = state
	}
	state.failures = append(recent(state.failures, now.Add(-l.window)), now)
	if len(state.failures) >= l.maxFailures {
		state.lockedUntil = now.Add(l.lockout)
		state.failures = nil
	}
}

func (l *LoginLimiter) prune(now time.Time) {
	cutoff := now.Add(-l.window)
	for key, state := range l.states {
		state.failures = recent(state.failures, cutoff)
		if !now.Before(state.lockedUntil) && len(state.failures) == 0 {
			delete(l.states, key)
		}
	}
}

func (l *LoginLimiter) Success(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.states, key)
}

func recent(values []time.Time, cutoff time.Time) []time.Time {
	first := 0
	for first < len(values) && values[first].Before(cutoff) {
		first++
	}
	return values[first:]
}
