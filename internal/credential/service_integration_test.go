package credential_test

import (
	"context"
	"database/sql"
	"strings"
	"testing"

	"github.com/rin721/certmate/internal/credential"
	"github.com/rin721/certmate/internal/store/sqlite"
	_ "modernc.org/sqlite"
)

func TestEncryptedCredentialNeverStoresOrReturnsPlaintext(t *testing.T) {
	ctx := context.Background()
	dataDir := t.TempDir()
	store, err := sqlite.Open(ctx, dataDir)
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
	service := credential.NewService(store, credential.NewRegistry(), cipher)
	created, err := service.Create(ctx, credential.CreateRequest{
		Name: "Cloudflare production", Provider: "cloudflare", SourceMode: "encrypted",
		Values: map[string]string{"CF_Token": "never-store-this-token"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(created.MaskedFields) != 1 || created.MaskedFields[0] != "CF_Token" {
		t.Fatalf("masked fields = %v", created.MaskedFields)
	}
	listed, err := service.List(ctx)
	if err != nil || len(listed) != 1 || len(listed[0].MaskedFields) != 1 {
		t.Fatalf("listed=%v err=%v", listed, err)
	}
	resolved, err := service.Resolve(ctx, created.ID)
	if err != nil || resolved.Environment["CF_Token"] != "never-store-this-token" || resolved.ACMEDNSCode != "dns_cf" {
		t.Fatalf("resolved=%v err=%v", resolved, err)
	}

	database, err := sql.Open("sqlite", dataDir+"/app.db")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	var encrypted []byte
	if err := database.QueryRowContext(ctx, `SELECT encrypted_values FROM dns_credentials WHERE id = ?`, created.ID).Scan(&encrypted); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encrypted), "never-store-this-token") {
		t.Fatal("数据库密文中出现明文 Token")
	}
}

func TestUpdateCredentialKeepsIDAndReplacesSecret(t *testing.T) {
	ctx := context.Background()
	store, err := sqlite.Open(ctx, t.TempDir())
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
	service := credential.NewService(store, credential.NewRegistry(), cipher)
	created, err := service.Create(ctx, credential.CreateRequest{
		Name: "Cloudflare old", Provider: "cloudflare", SourceMode: "encrypted",
		Values: map[string]string{"CF_Token": "old-secret"},
	})
	if err != nil {
		t.Fatal(err)
	}
	updated, err := service.Update(ctx, created.ID, credential.CreateRequest{
		Name: "Cloudflare new", Provider: "cloudflare", SourceMode: "encrypted",
		Values: map[string]string{"CF_Token": "new-secret"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if updated.ID != created.ID || updated.Name != "Cloudflare new" || !updated.UpdatedAt.After(created.UpdatedAt) {
		t.Fatalf("updated=%+v created=%+v", updated, created)
	}
	resolved, err := service.Resolve(ctx, created.ID)
	if err != nil || resolved.Environment["CF_Token"] != "new-secret" {
		t.Fatalf("resolved=%v err=%v", resolved, err)
	}
	if err := service.Test(ctx, created.ID); err != nil {
		t.Fatal(err)
	}
	renamed, err := service.Rename(ctx, created.ID, "Cloudflare renamed")
	if err != nil || renamed.ID != created.ID || renamed.Name != "Cloudflare renamed" {
		t.Fatalf("renamed=%+v err=%v", renamed, err)
	}
	resolved, err = service.Resolve(ctx, created.ID)
	if err != nil || resolved.Environment["CF_Token"] != "new-secret" {
		t.Fatalf("rename changed secret: resolved=%v err=%v", resolved, err)
	}
}
