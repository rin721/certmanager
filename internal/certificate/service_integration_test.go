package certificate_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/rin721/certmate/internal/certificate"
	"github.com/rin721/certmate/internal/certificate/acmesh"
	certfiles "github.com/rin721/certmate/internal/certificate/files"
	"github.com/rin721/certmate/internal/certificate/parser"
	"github.com/rin721/certmate/internal/certificate/selfsigned"
	"github.com/rin721/certmate/internal/credential"
	"github.com/rin721/certmate/internal/store/sqlite"
)

type fakeSelfSignedEngine struct{}

type failingRenewSelfSignedEngine struct{}

type blockingSelfSignedEngine struct {
	started chan struct{}
	release chan struct{}
}

func (b *blockingSelfSignedEngine) Issue(_ context.Context, request selfsigned.Request) (*selfsigned.Result, error) {
	return generatedFixture(request)
}

func (b *blockingSelfSignedEngine) Renew(_ context.Context, request selfsigned.Request) (*selfsigned.Result, error) {
	close(b.started)
	<-b.release
	return generatedFixture(request)
}

type fakeACMEEngine struct {
	request acmesh.IssueRequest
}

func (f *fakeACMEEngine) Issue(_ context.Context, request acmesh.IssueRequest) (*acmesh.Result, error) {
	f.request = request
	fixture, err := generatedFixture(selfsigned.Request{PrimaryDomain: request.PrimaryDomain, Domains: request.Domains, KeyType: request.KeyType, ValidDays: 90})
	if err != nil {
		return nil, err
	}
	return &acmesh.Result{
		CertificatePEM: fixture.CertificatePEM, ChainPEM: fixture.CertificatePEM,
		FullchainPEM: fixture.CertificatePEM, PrivateKeyPEM: fixture.PrivateKeyPEM, Metadata: fixture.Metadata,
	}, nil
}

func (f *fakeACMEEngine) Renew(context.Context, acmesh.RenewRequest) (*acmesh.Result, error) {
	return nil, nil
}
func (f *fakeACMEEngine) Revoke(context.Context, acmesh.RevokeRequest) error { return nil }
func (f *fakeACMEEngine) Remove(context.Context, string) error               { return nil }
func (f *fakeACMEEngine) Info(context.Context, string) (*acmesh.CertificateInfo, error) {
	return &acmesh.CertificateInfo{}, nil
}

func (fakeSelfSignedEngine) Issue(_ context.Context, request selfsigned.Request) (*selfsigned.Result, error) {
	return generatedFixture(request)
}

func (fakeSelfSignedEngine) Renew(ctx context.Context, request selfsigned.Request) (*selfsigned.Result, error) {
	return fakeSelfSignedEngine{}.Issue(ctx, request)
}

func (failingRenewSelfSignedEngine) Issue(_ context.Context, request selfsigned.Request) (*selfsigned.Result, error) {
	return generatedFixture(request)
}

func (failingRenewSelfSignedEngine) Renew(context.Context, selfsigned.Request) (*selfsigned.Result, error) {
	return nil, errors.New("simulated OpenSSL failure")
}

func TestCreateSelfSignedVerticalSlice(t *testing.T) {
	ctx := context.Background()
	dataDir := filepath.Join(t.TempDir(), "data")
	certDir := filepath.Join(t.TempDir(), "certs")
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
	service := certificate.NewService(store, fakeSelfSignedEngine{}, certfiles.NewPublisher(certDir, filepath.Join(dataDir, "backups")), nil, nil)
	value, err := service.CreateSelfSigned(ctx, certificate.CreateSelfSignedRequest{
		Name: "测试证书", PrimaryDomain: "example.com", SANs: []string{"www.example.com"},
		KeyType: "ec-256", ValidDays: 90, OutputDirectory: "example-com",
		AutoRenewEnabled: true, RenewBeforeDays: 15, CreateRenewedMarker: true,
	}, "admin", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if value.Status != certificate.StatusActive || value.NotAfter == nil || value.FingerprintSHA256 == "" {
		t.Fatalf("certificate = %+v", value)
	}
	privateKey, err := os.ReadFile(filepath.Join(certDir, "example-com", "privkey.pem"))
	if err != nil || len(privateKey) == 0 {
		t.Fatalf("私钥未发布: %v", err)
	}
	if info, err := os.Stat(filepath.Join(certDir, "example-com", "privkey.pem")); err != nil || (runtime.GOOS != "windows" && info.Mode().Perm() != 0o600) {
		t.Fatalf("私钥权限错误: info=%v err=%v", info, err)
	}
	items, err := service.List(ctx)
	if err != nil || len(items) != 1 || items[0].ID != value.ID {
		t.Fatalf("list=%v err=%v", items, err)
	}
	updated, err := service.Update(ctx, value.ID, certificate.UpdateRequest{Name: "新名称", AutoRenewEnabled: false, RenewBeforeDays: 20, CreateRenewedMarker: false}, "admin", "127.0.0.1")
	if err != nil || updated.Name != "新名称" || updated.AutoRenewEnabled || updated.RenewBeforeDays != 20 || updated.CreateRenewedMarker {
		t.Fatalf("updated=%+v err=%v", updated, err)
	}
}

func TestFailedRenewalKeepsPublishedFiles(t *testing.T) {
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
	service := certificate.NewService(store, failingRenewSelfSignedEngine{}, certfiles.NewPublisher(certDir, filepath.Join(dataDir, "backups")), nil, nil)
	value, err := service.CreateSelfSigned(ctx, certificate.CreateSelfSignedRequest{
		Name: "保留旧文件", PrimaryDomain: "example.com", KeyType: "ec-256", ValidDays: 90,
		OutputDirectory: "example-com", AutoRenewEnabled: true, RenewBeforeDays: 15,
	}, "admin", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	filename := filepath.Join(certDir, "example-com", "privkey.pem")
	before, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Renew(ctx, value.ID, false, "admin", "127.0.0.1"); err == nil {
		t.Fatal("续签失败必须返回错误")
	}
	after, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatal("续签失败覆盖了上一份可用私钥")
	}
}

func TestCreateACMEVerticalSliceWithFakeEngine(t *testing.T) {
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
	cipher, err := credential.NewCipher([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	credentialService := credential.NewService(store, credential.NewRegistry(), cipher)
	dnsCredential, err := credentialService.Create(ctx, credential.CreateRequest{
		Name: "Cloudflare", Provider: "cloudflare", SourceMode: "encrypted",
		Values: map[string]string{"CF_Token": "secret-token"},
	})
	if err != nil {
		t.Fatal(err)
	}
	engine := &fakeACMEEngine{}
	service := certificate.NewService(store, nil, certfiles.NewPublisher(certDir, filepath.Join(dataDir, "backups")), engine, credentialService)
	value, err := service.CreateACME(ctx, certificate.CreateACMERequest{
		Name: "公共证书", PrimaryDomain: "example.com", SANs: []string{"www.example.com"}, KeyType: "ec-256",
		OutputDirectory: "example-com", AutoRenewEnabled: true, RenewBeforeDays: 30,
		CreateRenewedMarker: true, ChallengeType: "dns-01", DNSCredentialID: dnsCredential.ID,
		CADirectoryURL: "letsencrypt_test", ACMEEmail: "admin@example.com",
	}, "admin", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if value.Mode != certificate.ModeACME || value.Status != certificate.StatusActive {
		t.Fatalf("certificate=%+v", value)
	}
	if engine.request.DNSProvider != "dns_cf" || engine.request.DNSVariables["CF_Token"] != "secret-token" {
		t.Fatalf("engine request=%+v", engine.request)
	}
	if _, err := os.Stat(filepath.Join(certDir, "example-com", "fullchain.pem")); err != nil {
		t.Fatal(err)
	}
}

func TestSameCertificateRenewalIsMutuallyExclusive(t *testing.T) {
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
	engine := &blockingSelfSignedEngine{started: make(chan struct{}), release: make(chan struct{})}
	service := certificate.NewService(store, engine, certfiles.NewPublisher(certDir, filepath.Join(dataDir, "backups")), nil, nil)
	value, err := service.CreateSelfSigned(ctx, certificate.CreateSelfSignedRequest{
		Name: "互斥测试", PrimaryDomain: "example.com", KeyType: "ec-256", ValidDays: 90,
		OutputDirectory: "example-com", AutoRenewEnabled: true, RenewBeforeDays: 15,
	}, "admin", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	firstDone := make(chan error, 1)
	go func() {
		_, renewErr := service.Renew(ctx, value.ID, false, "admin", "127.0.0.1")
		firstDone <- renewErr
	}()
	select {
	case <-engine.started:
	case <-time.After(time.Second):
		t.Fatal("首次续签未进入 Engine")
	}
	if _, err := service.Renew(ctx, value.ID, false, "admin", "127.0.0.1"); !errors.Is(err, certificate.ErrOperationRunning) {
		t.Fatalf("重复续签 err=%v", err)
	}
	close(engine.release)
	if err := <-firstDone; err != nil {
		t.Fatal(err)
	}
}

func generatedFixture(request selfsigned.Request) (*selfsigned.Result, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(42), Subject: pkix.Name{CommonName: request.PrimaryDomain},
		Issuer: pkix.Name{CommonName: request.PrimaryDomain}, NotBefore: now.Add(-time.Minute),
		NotAfter: now.Add(time.Duration(request.ValidDays) * 24 * time.Hour), DNSNames: request.Domains,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	privatePEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	_, metadata, err := parser.ParseCertificate(certificatePEM)
	if err != nil {
		return nil, err
	}
	return &selfsigned.Result{CertificatePEM: certificatePEM, PrivateKeyPEM: privatePEM, Metadata: metadata}, nil
}
