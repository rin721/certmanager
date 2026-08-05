package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rin721/certmate/internal/auth"
	"github.com/rin721/certmate/internal/certificate"
	"github.com/rin721/certmate/internal/certificate/acmesh"
	certfiles "github.com/rin721/certmate/internal/certificate/files"
	"github.com/rin721/certmate/internal/config"
	"github.com/rin721/certmate/internal/credential"
	"github.com/rin721/certmate/internal/jobs"
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

type cloudflareZoneFailureEngine struct{}

func (cloudflareZoneFailureEngine) Issue(context.Context, acmesh.IssueRequest) (*acmesh.Result, error) {
	return nil, cloudflareZoneCommandError("issue")
}

func (cloudflareZoneFailureEngine) Renew(context.Context, acmesh.RenewRequest) (*acmesh.Result, error) {
	return nil, cloudflareZoneCommandError("renew")
}

func (cloudflareZoneFailureEngine) Revoke(context.Context, acmesh.RevokeRequest) error { return nil }
func (cloudflareZoneFailureEngine) Remove(context.Context, string) error               { return nil }
func (cloudflareZoneFailureEngine) Info(context.Context, string) (*acmesh.CertificateInfo, error) {
	return &acmesh.CertificateInfo{}, nil
}

func cloudflareZoneCommandError(operation string) error {
	return &acmesh.CommandError{
		Operation: operation, ExitCode: 1, Retryable: true, Kind: acmesh.FailureDNSZoneUnavailable,
		Summary: "Adding TXT value: [REDACTED] for domain: _acme-challenge.example.com\ninvalid domain\nError adding TXT record to domain: _acme-challenge.example.com",
		Cause:   errors.New("exit status 1"),
	}
}

func TestCertificateAPIReturnsCloudflareZoneErrorForCreateIssueAndRenew(t *testing.T) {
	ctx := context.Background()
	store, err := sqlite.Open(ctx, filepath.Join(t.TempDir(), "data"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	cipher, err := credential.NewCipher([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	credentialService := credential.NewService(store, credential.NewRegistry(), cipher)
	credentialValue := strings.Repeat("x", 32)
	cloudflareCredential, err := credentialService.Create(ctx, credential.CreateRequest{
		Name: "Cloudflare", Provider: "cloudflare", SourceMode: "encrypted",
		Values: map[string]string{"CF_Token": credentialValue},
	})
	if err != nil {
		t.Fatal(err)
	}
	service := certificate.NewService(store, nil, nil, cloudflareZoneFailureEngine{}, credentialService)
	server, client, csrfToken := newAuthenticatedCertificateServer(t, store, service)
	expectedMessage := "Cloudflare 无法访问域名 \"example.com\" 的 Zone；请确认 Token 有效，具备 Zone:Zone:Read 和 Zone:DNS:Edit 权限，资源范围包含该 Zone，且 Token IP 限制允许当前服务器"

	response := postJSON(t, client, server.URL+"/api/v1/certificates", csrfToken, map[string]any{
		"mode": "acme", "name": "Cloudflare 失败证书", "primary_domain": "example.com",
		"sans": []string{"*.example.com"}, "key_type": "ec-256", "output_directory": "example-com",
		"auto_renew_enabled": true, "renew_before_days": 30, "challenge_type": "dns-01",
		"dns_credential_id": cloudflareCredential.ID, "ca_directory_url": "letsencrypt", "acme_email": "admin@example.com",
	})
	assertCertificateErrorMessage(t, response, http.StatusBadRequest, "CERT_DNS_ZONE_UNAVAILABLE", expectedMessage)

	values, err := store.Certificates(ctx)
	if err != nil || len(values) != 1 {
		t.Fatalf("创建失败记录异常: values=%+v err=%v", values, err)
	}
	failed := values[0]
	if failed.Status != certificate.StatusFailed || failed.LastError != expectedMessage {
		t.Fatalf("失败记录未保存安全诊断: status=%s last_error=%q", failed.Status, failed.LastError)
	}
	runs, err := store.Jobs(ctx, jobs.Query{CertificateID: failed.ID})
	if err != nil || len(runs) != 1 || runs[0].ErrorMessage != expectedMessage || strings.Contains(runs[0].ErrorMessage, credentialValue) {
		t.Fatalf("任务诊断未正确脱敏: runs=%+v err=%v", runs, err)
	}

	response = postJSON(t, client, server.URL+"/api/v1/certificates/"+failed.ID+"/issue", csrfToken, nil)
	assertCertificateErrorMessage(t, response, http.StatusBadRequest, "CERT_DNS_ZONE_UNAVAILABLE", expectedMessage)

	active := certificate.Certificate{
		ID: "cloudflare-active", Name: "Cloudflare 续签证书", Mode: certificate.ModeACME,
		PrimaryDomain: "example.com", Domains: []string{"example.com", "*.example.com"}, KeyType: "ec-256",
		Status: certificate.StatusActive, OutputDirectory: "cloudflare-active", AutoRenewEnabled: true,
		RenewBeforeDays: 30, ChallengeType: "dns-01", DNSProvider: "dns_cf",
		DNSCredentialID: cloudflareCredential.ID, CADirectoryURL: "letsencrypt", ACMEEmail: "admin@example.com",
	}
	if err := store.CreateCertificate(ctx, &active); err != nil {
		t.Fatal(err)
	}
	response = postJSON(t, client, server.URL+"/api/v1/certificates/"+active.ID+"/renew", csrfToken, nil)
	assertCertificateErrorMessage(t, response, http.StatusBadRequest, "CERT_DNS_ZONE_UNAVAILABLE", expectedMessage)
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

func TestCertificateAPIDeletesFailedRecordWithoutPublishedFiles(t *testing.T) {
	ctx := context.Background()
	dataDir, certDir := filepath.Join(t.TempDir(), "data"), filepath.Join(t.TempDir(), "certs")
	if err := os.Mkdir(certDir, 0o750); err != nil {
		t.Fatal(err)
	}
	store, err := sqlite.Open(ctx, dataDir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	value := certificate.Certificate{
		ID: "failed-delete", Name: "失败记录", Mode: certificate.ModeACME, PrimaryDomain: "example.com",
		Domains: []string{"example.com"}, KeyType: "ec-256", Status: certificate.StatusFailed,
		OutputDirectory: "failed-delete", RenewBeforeDays: 30,
	}
	if err := store.CreateCertificate(ctx, &value); err != nil {
		t.Fatal(err)
	}
	service := certificate.NewService(store, nil, certfiles.NewPublisher(certDir, filepath.Join(dataDir, "backups")), unusedACMEEngine{}, nil)
	server, client, csrfToken := newAuthenticatedCertificateServer(t, store, service)

	response, err := client.Get(server.URL + "/api/v1/certificates/" + value.ID + "/files")
	if err != nil {
		t.Fatal(err)
	}
	var filesResponse struct {
		Items []map[string]any `json:"items"`
	}
	if err := json.NewDecoder(response.Body).Decode(&filesResponse); err != nil {
		response.Body.Close()
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK || len(filesResponse.Items) != 0 {
		t.Fatalf("文件列表 status=%d items=%+v", response.StatusCode, filesResponse.Items)
	}

	response = requestJSONMethod(t, client, http.MethodDelete, server.URL+"/api/v1/certificates/"+value.ID, csrfToken, map[string]any{
		"password": "correct-password", "confirm_name": value.Name, "delete_files": true,
	})
	defer response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(response.Body)
		t.Fatalf("status=%d body=%s", response.StatusCode, body)
	}
}

func TestCertificateAPIReturnsStableErrorsForInvalidRevokeAndBackupFailure(t *testing.T) {
	ctx := context.Background()
	dataDir, certDir := filepath.Join(t.TempDir(), "data"), filepath.Join(t.TempDir(), "certs")
	partialDir := filepath.Join(certDir, "partial-certificate")
	if err := os.MkdirAll(partialDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(partialDir, "cert.pem"), []byte("partial"), 0o644); err != nil {
		t.Fatal(err)
	}
	store, err := sqlite.Open(ctx, dataDir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	value := certificate.Certificate{
		ID: "failed-actions", Name: "失败操作", Mode: certificate.ModeACME, PrimaryDomain: "example.com",
		Domains: []string{"example.com"}, KeyType: "ec-256", Status: certificate.StatusFailed,
		OutputDirectory: "partial-certificate", RenewBeforeDays: 30,
	}
	if err := store.CreateCertificate(ctx, &value); err != nil {
		t.Fatal(err)
	}
	service := certificate.NewService(store, nil, certfiles.NewPublisher(certDir, filepath.Join(dataDir, "backups")), unusedACMEEngine{}, nil)
	server, client, csrfToken := newAuthenticatedCertificateServer(t, store, service)

	response := requestJSONMethod(t, client, http.MethodPost, server.URL+"/api/v1/certificates/"+value.ID+"/revoke", csrfToken, map[string]any{"password": "correct-password"})
	assertCertificateError(t, response, http.StatusConflict, "CERT_REVOKE_NOT_ALLOWED")
	runs, err := store.Jobs(ctx, jobs.Query{CertificateID: value.ID, JobType: "revoke"})
	if err != nil || len(runs) != 0 {
		t.Fatalf("非法撤销不应创建任务: runs=%+v err=%v", runs, err)
	}

	response = requestJSONMethod(t, client, http.MethodDelete, server.URL+"/api/v1/certificates/"+value.ID, csrfToken, map[string]any{
		"password": "correct-password", "confirm_name": value.Name, "delete_files": true,
	})
	assertCertificateError(t, response, http.StatusConflict, "CERT_DELETE_FILES_BACKUP_FAILED")
	if _, err := store.Certificate(ctx, value.ID); err != nil {
		t.Fatalf("备份失败时管理记录必须保留: %v", err)
	}
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

func assertCertificateErrorMessage(t *testing.T, response *http.Response, status int, code, message string) {
	t.Helper()
	defer response.Body.Close()
	if response.StatusCode != status {
		body, _ := io.ReadAll(response.Body)
		t.Fatalf("status=%d body=%s", response.StatusCode, body)
	}
	var body errorBody
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.Error.Code != code || body.Error.Message != message {
		t.Fatalf("error=%+v", body.Error)
	}
}

func requestJSONMethod(t *testing.T, client *http.Client, method, url, csrfToken string, value any) *http.Response {
	t.Helper()
	payload, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(method, url, bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-CSRF-Token", csrfToken)
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func assertCertificateError(t *testing.T, response *http.Response, status int, code string) {
	t.Helper()
	defer response.Body.Close()
	if response.StatusCode != status {
		body, _ := io.ReadAll(response.Body)
		t.Fatalf("status=%d body=%s", response.StatusCode, body)
	}
	var body errorBody
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.Error.Code != code {
		t.Fatalf("error=%+v", body.Error)
	}
}
