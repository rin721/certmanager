package httpapi

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rin721/certmate/internal/auth"
	"github.com/rin721/certmate/internal/config"
)

func TestRouterHealthMetaAndSPAFallback(t *testing.T) {
	t.Parallel()
	cfg := config.Config{
		AppName:           "CertMate Test",
		Environment:       "test",
		EnableACME:        true,
		EnableSelfSigned:  true,
		AdminUsername:     "admin",
		AdminPasswordHash: []byte("$2a$10$7EqJtq98hPqEX7fNZaFWoO5HSt2NmR1FONpDqxdAZD9hvmBtT2LzG"),
		SessionSecret:     []byte("test-session-secret-at-least-32-bytes"),
		SessionTTL:        time.Hour,
	}
	server := httptest.NewServer(NewRouter(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), auth.NewManager(cfg), nil, nil, nil, nil, nil))
	t.Cleanup(server.Close)

	for _, endpoint := range []string{"/healthz", "/readyz"} {
		response, err := http.Get(server.URL + endpoint)
		if err != nil {
			t.Fatalf("GET %s: %v", endpoint, err)
		}
		if response.StatusCode != http.StatusOK {
			response.Body.Close()
			t.Fatalf("GET %s status = %d", endpoint, response.StatusCode)
		}
		response.Body.Close()
	}

	response, err := http.Get(server.URL + "/api/v1/meta")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var meta map[string]any
	if err := json.NewDecoder(response.Body).Decode(&meta); err != nil {
		t.Fatal(err)
	}
	if meta["app_name"] != "CertMate Test" {
		t.Fatalf("app_name = %v", meta["app_name"])
	}

	response, err = http.Get(server.URL + "/certificates/example")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || !strings.Contains(string(body), `<div id="root"`) {
		t.Fatalf("SPA fallback status=%d body=%q", response.StatusCode, body)
	}
}
