package httpapi

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/rin721/certmate/internal/auth"
	"github.com/rin721/certmate/internal/certificate"
	"github.com/rin721/certmate/internal/certificate/acmesh"
	"github.com/rin721/certmate/internal/config"
	"github.com/rin721/certmate/internal/store/sqlite"
	"golang.org/x/crypto/bcrypt"
)

type unusedACMEEngine struct{}

func (unusedACMEEngine) Issue(context.Context, acmesh.IssueRequest) (*acmesh.Result, error) {
	panic("冗余域名不应调用 ACME 签发引擎")
}

func (unusedACMEEngine) Renew(context.Context, acmesh.RenewRequest) (*acmesh.Result, error) {
	panic("冗余域名不应调用 ACME 续签引擎")
}

func (unusedACMEEngine) Revoke(context.Context, acmesh.RevokeRequest) error { return nil }
func (unusedACMEEngine) Remove(context.Context, string) error               { return nil }
func (unusedACMEEngine) Info(context.Context, string) (*acmesh.CertificateInfo, error) {
	return &acmesh.CertificateInfo{}, nil
}

func TestCertificateAPIReturnsRedundantDomainErrorForCreateAndIssue(t *testing.T) {
	ctx := context.Background()
	store, err := sqlite.Open(ctx, filepath.Join(t.TempDir(), "data"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	service := certificate.NewService(store, nil, nil, unusedACMEEngine{}, nil)
	server, client, csrfToken := newAuthenticatedCertificateServer(t, store, service)

	response := postJSON(t, client, server.URL+"/api/v1/certificates", csrfToken, map[string]any{
		"mode": "acme", "name": "冗余公共证书", "primary_domain": "example.com",
		"sans": []string{"*.example.com", "www.example.com"}, "key_type": "ec-256",
		"output_directory": "example-com", "auto_renew_enabled": true, "renew_before_days": 30,
		"challenge_type": "http-01", "ca_directory_url": "letsencrypt", "acme_email": "admin@example.com",
	})
	assertRedundantDomainResponse(t, response, "SAN 域名 \"www.example.com\" 已被通配符 \"*.example.com\" 覆盖，请删除其中一个")

	legacy := certificate.Certificate{
		ID: "legacy-failed", Name: "旧失败证书", Mode: certificate.ModeACME, PrimaryDomain: "example.com",
		Domains: []string{"example.com", "*.example.com", "www.example.com"}, KeyType: "ec-256",
		Status: certificate.StatusFailed, OutputDirectory: "example-com", RenewBeforeDays: 30,
		ChallengeType: "http-01", CADirectoryURL: "letsencrypt", ACMEEmail: "admin@example.com",
	}
	if err := store.CreateCertificate(ctx, &legacy); err != nil {
		t.Fatal(err)
	}
	response = postJSON(t, client, server.URL+"/api/v1/certificates/"+legacy.ID+"/issue", csrfToken, nil)
	assertRedundantDomainResponse(t, response, "SAN 域名 \"www.example.com\" 已被通配符 \"*.example.com\" 覆盖，请删除其中一个")
}

func newAuthenticatedCertificateServer(t *testing.T, store *sqlite.Store, service *certificate.Service) (*httptest.Server, *http.Client, string) {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte("correct-password"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{
		AppName: "CertMate Test", Environment: "test", AdminUsername: "admin", AdminPasswordHash: hash,
		SessionSecret: []byte("test-session-secret-at-least-32-bytes"), SessionTTL: time.Hour,
	}
	server := httptest.NewServer(NewRouter(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), auth.NewManager(cfg), store, service, nil, nil, nil))
	t.Cleanup(server.Close)
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Jar: jar}
	response, err := client.Get(server.URL + "/api/v1/auth/csrf")
	if err != nil {
		t.Fatal(err)
	}
	var tokenResponse map[string]string
	if err := json.NewDecoder(response.Body).Decode(&tokenResponse); err != nil {
		response.Body.Close()
		t.Fatal(err)
	}
	response.Body.Close()
	csrfToken := tokenResponse["csrf_token"]
	response = postJSON(t, client, server.URL+"/api/v1/auth/login", csrfToken, map[string]string{"username": "admin", "password": "correct-password"})
	if response.StatusCode != http.StatusOK {
		response.Body.Close()
		t.Fatalf("登录 status=%d", response.StatusCode)
	}
	response.Body.Close()
	return server, client, csrfToken
}

func assertRedundantDomainResponse(t *testing.T, response *http.Response, expectedMessage string) {
	t.Helper()
	defer response.Body.Close()
	if response.StatusCode != http.StatusBadRequest {
		body, _ := io.ReadAll(response.Body)
		t.Fatalf("status=%d body=%s", response.StatusCode, body)
	}
	var body errorBody
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.Error.Code != "CERT_DOMAIN_REDUNDANT" || body.Error.Message != expectedMessage {
		t.Fatalf("error=%+v", body.Error)
	}
}
