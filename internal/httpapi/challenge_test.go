package httpapi

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rin721/certmate/internal/auth"
	"github.com/rin721/certmate/internal/config"
)

func TestHTTPChallengeOnlyServesWhitelistedRegularFile(t *testing.T) {
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, "safe_Token-123"), []byte("challenge-value"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{
		AppName: "test", Environment: "test", ACMEChallengeDir: directory,
		AdminUsername: "admin", AdminPasswordHash: []byte("$2a$10$7EqJtq98hPqEX7fNZaFWoO5HSt2NmR1FONpDqxdAZD9hvmBtT2LzG"),
		SessionSecret: []byte("test-session-secret-at-least-32-bytes"), SessionTTL: time.Hour,
	}
	server := httptest.NewServer(NewRouter(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), auth.NewManager(cfg), nil, nil, nil, nil, nil))
	t.Cleanup(server.Close)
	response, err := http.Get(server.URL + "/.well-known/acme-challenge/safe_Token-123")
	if err != nil {
		t.Fatal(err)
	}
	value, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusOK || string(value) != "challenge-value" {
		t.Fatalf("status=%d body=%q", response.StatusCode, value)
	}
	for _, path := range []string{"../secret", "%2e%2e%2fsecret", "safe.Token"} {
		response, err := http.Get(server.URL + "/.well-known/acme-challenge/" + path)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode == http.StatusOK {
			t.Fatalf("非法 token %q 不得返回 200", path)
		}
	}
}
