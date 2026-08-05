package httpapi

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/gorilla/csrf"
	"github.com/rin721/certmate/internal/auth"
)

const maxAuthBody = 16 << 10

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type passwordRequest struct {
	Password string `json:"password"`
}

func (rt *Router) csrfToken(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]string{"csrf_token": csrf.Token(r)})
}

func (rt *Router) login(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	var request loginRequest
	if err := decodeJSON(w, r, &request, maxAuthBody); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "请求格式无效")
		return
	}
	err := rt.auth.Authenticate(auth.ClientIP(r, rt.config.TrustsProxy(r.RemoteAddr)), request.Username, request.Password)
	request.Password = ""
	if errors.Is(err, auth.ErrRateLimited) {
		rt.auditAdminEvent(r, "auth.login", "unknown", "rate_limited", nil)
		rt.logger.WarnContext(r.Context(), "login rate limited", "client_ip", auth.ClientIP(r, rt.config.TrustsProxy(r.RemoteAddr)))
		writeError(w, http.StatusTooManyRequests, "AUTH_RATE_LIMITED", "登录尝试过于频繁，请稍后重试")
		return
	}
	if err != nil {
		rt.auditAdminEvent(r, "auth.login", "unknown", "failed", nil)
		rt.logger.WarnContext(r.Context(), "login failed", "client_ip", auth.ClientIP(r, rt.config.TrustsProxy(r.RemoteAddr)))
		writeError(w, http.StatusUnauthorized, "AUTH_INVALID_CREDENTIALS", "用户名或密码错误")
		return
	}
	if err := rt.auth.Login(w, r); err != nil {
		rt.logger.ErrorContext(r.Context(), "session creation failed", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "登录暂时不可用")
		return
	}
	rt.logger.InfoContext(r.Context(), "login succeeded", "client_ip", auth.ClientIP(r, rt.config.TrustsProxy(r.RemoteAddr)))
	rt.auditAdminEvent(r, "auth.login", request.Username, "succeeded", nil)
	writeJSON(w, http.StatusOK, map[string]any{"username": request.Username, "authenticated": true})
}

func (rt *Router) logout(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	actor, _ := rt.auth.CurrentUser(r)
	if err := rt.auth.Logout(w, r); err != nil {
		rt.logger.ErrorContext(r.Context(), "session deletion failed", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "退出失败")
		return
	}
	rt.auditAdminEvent(r, "auth.logout", actor, "succeeded", nil)
	writeJSON(w, http.StatusOK, map[string]bool{"authenticated": false})
}

func (rt *Router) me(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	username, ok := rt.auth.CurrentUser(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "AUTH_REQUIRED", "请先登录")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"username":        username,
		"authenticated":   true,
		"reauthenticated": rt.auth.Reauthenticated(r),
	})
}

func (rt *Router) reauthenticate(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	var request passwordRequest
	if err := decodeJSON(w, r, &request, maxAuthBody); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "请求格式无效")
		return
	}
	err := rt.auth.Reauthenticate(w, r, request.Password)
	request.Password = ""
	if errors.Is(err, auth.ErrInvalidCredentials) {
		rt.auditAdminEvent(r, "auth.reauthenticate", "admin", "failed", nil)
		writeError(w, http.StatusUnauthorized, "AUTH_INVALID_CREDENTIALS", "密码错误")
		return
	}
	if errors.Is(err, auth.ErrUnauthenticated) {
		writeError(w, http.StatusUnauthorized, "AUTH_REQUIRED", "请先登录")
		return
	}
	if err != nil {
		rt.logger.ErrorContext(r.Context(), "reauthentication failed", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "重新认证失败")
		return
	}
	rt.auditAdminEvent(r, "auth.reauthenticate", "admin", "succeeded", nil)
	writeJSON(w, http.StatusOK, map[string]bool{"reauthenticated": true})
}

func (rt *Router) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := rt.auth.CurrentUser(r); !ok {
			writeError(w, http.StatusUnauthorized, "AUTH_REQUIRED", "请先登录")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func decodeJSON(w http.ResponseWriter, r *http.Request, destination any, limit int64) error {
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("请求体只能包含一个 JSON 对象")
	}
	return nil
}
