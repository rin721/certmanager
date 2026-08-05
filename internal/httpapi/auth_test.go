package httpapi

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/rin721/certmate/internal/auth"
	"github.com/rin721/certmate/internal/config"
	"golang.org/x/crypto/bcrypt"
)

func TestAuthenticationFlowRequiresCSRFAndUsesCookieSession(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("correct-password"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{
		AppName:           "CertMate Test",
		Environment:       "test",
		AdminUsername:     "admin",
		AdminPasswordHash: hash,
		SessionSecret:     []byte("test-session-secret-at-least-32-bytes"),
		SessionTTL:        time.Hour,
	}
	server := httptest.NewServer(NewRouter(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), auth.NewManager(cfg), nil, nil, nil, nil, nil))
	t.Cleanup(server.Close)
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Jar: jar}

	response := postJSON(t, client, server.URL+"/api/v1/auth/login", "", map[string]string{"username": "admin", "password": "correct-password"})
	if response.StatusCode != http.StatusForbidden {
		response.Body.Close()
		t.Fatalf("无 CSRF 登录 status=%d", response.StatusCode)
	}
	response.Body.Close()

	response, err = client.Get(server.URL + "/api/v1/auth/csrf")
	if err != nil {
		t.Fatal(err)
	}
	var tokenResponse map[string]string
	if err := json.NewDecoder(response.Body).Decode(&tokenResponse); err != nil {
		response.Body.Close()
		t.Fatal(err)
	}
	response.Body.Close()
	token := tokenResponse["csrf_token"]
	if token == "" {
		t.Fatal("CSRF token 不能为空")
	}

	response = postJSON(t, client, server.URL+"/api/v1/auth/login", token, map[string]string{"username": "admin", "password": "wrong"})
	if response.StatusCode != http.StatusUnauthorized {
		body, _ := io.ReadAll(response.Body)
		response.Body.Close()
		t.Fatalf("错误密码 status=%d body=%s cookies=%v", response.StatusCode, body, jar.Cookies(response.Request.URL))
	}
	response.Body.Close()

	response = postJSON(t, client, server.URL+"/api/v1/auth/login", token, map[string]string{"username": "admin", "password": "correct-password"})
	if response.StatusCode != http.StatusOK {
		response.Body.Close()
		t.Fatalf("正确登录 status=%d", response.StatusCode)
	}
	response.Body.Close()

	response, err = client.Get(server.URL + "/api/v1/auth/me")
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		response.Body.Close()
		t.Fatalf("登录后的 /me status=%d", response.StatusCode)
	}
	response.Body.Close()

	response = postJSON(t, client, server.URL+"/api/v1/auth/logout", token, nil)
	if response.StatusCode != http.StatusOK {
		response.Body.Close()
		t.Fatalf("退出 status=%d", response.StatusCode)
	}
	response.Body.Close()
	response, err = client.Get(server.URL + "/api/v1/auth/me")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("退出后的 /me status=%d", response.StatusCode)
	}
}

func postJSON(t *testing.T, client *http.Client, url, csrfToken string, value any) *http.Response {
	t.Helper()
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	if csrfToken != "" {
		request.Header.Set("X-CSRF-Token", csrfToken)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	return response
}
