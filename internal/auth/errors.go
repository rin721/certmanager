// Package auth 实现单管理员认证、会话和登录防护。
package auth

import "errors"

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrRateLimited        = errors.New("rate limited")
	ErrUnauthenticated    = errors.New("unauthenticated")
	ErrReauthRequired     = errors.New("reauthentication required")
)
