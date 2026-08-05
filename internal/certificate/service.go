package certificate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/rin721/certmate/internal/audit"
	"github.com/rin721/certmate/internal/certificate/acmesh"
	certfiles "github.com/rin721/certmate/internal/certificate/files"
	"github.com/rin721/certmate/internal/certificate/selfsigned"
	"github.com/rin721/certmate/internal/credential"
	"github.com/rin721/certmate/internal/jobs"
	"github.com/rin721/certmate/internal/scheduler"
)

var (
	ErrNotFound         = errors.New("certificate not found")
	ErrOperationRunning = errors.New("certificate operation already running")
)

type CreateSelfSignedRequest struct {
	Name                string   `json:"name"`
	PrimaryDomain       string   `json:"primary_domain"`
	SANs                []string `json:"sans"`
	KeyType             string   `json:"key_type"`
	ValidDays           int      `json:"valid_days"`
	OutputDirectory     string   `json:"output_directory"`
	AutoRenewEnabled    bool     `json:"auto_renew_enabled"`
	RenewBeforeDays     int      `json:"renew_before_days"`
	CreateRenewedMarker bool     `json:"create_renewed_marker"`
}

type CreateACMERequest struct {
	Name                string   `json:"name"`
	PrimaryDomain       string   `json:"primary_domain"`
	SANs                []string `json:"sans"`
	KeyType             string   `json:"key_type"`
	OutputDirectory     string   `json:"output_directory"`
	AutoRenewEnabled    bool     `json:"auto_renew_enabled"`
	RenewBeforeDays     int      `json:"renew_before_days"`
	CreateRenewedMarker bool     `json:"create_renewed_marker"`
	ChallengeType       string   `json:"challenge_type"`
	DNSCredentialID     string   `json:"dns_credential_id"`
	CADirectoryURL      string   `json:"ca_directory_url"`
	ACMEEmail           string   `json:"acme_email"`
}

type UpdateRequest struct {
	Name                string `json:"name"`
	AutoRenewEnabled    bool   `json:"auto_renew_enabled"`
	RenewBeforeDays     int    `json:"renew_before_days"`
	CreateRenewedMarker bool   `json:"create_renewed_marker"`
}

type Service struct {
	store       Repository
	engine      selfsigned.Engine
	publisher   *certfiles.Publisher
	acme        acmesh.ACMEEngine
	credentials interface {
		Resolve(context.Context, string) (credential.ProcessValues, error)
	}
	locks sync.Map
	now   func() time.Time
}

type Repository interface {
	CreateCertificate(context.Context, *Certificate) error
	Certificate(context.Context, string) (Certificate, error)
	Certificates(context.Context) ([]Certificate, error)
	MarkCertificateIssued(context.Context, Certificate) error
	MarkCertificateFailed(context.Context, string, string) error
	MarkCertificateRenewed(context.Context, Certificate) error
	SetCertificateStatus(context.Context, string, Status) error
	UpdateCertificateSettings(context.Context, string, string, bool, int, bool) error
	DeleteCertificate(context.Context, string) error
	CreateJob(context.Context, *jobs.Run) error
	FinishJob(context.Context, string, string, int, string, string) error
	CreateAuditEvent(context.Context, *audit.Event) error
}

func (s *Service) Update(ctx context.Context, id string, request UpdateRequest, actor, clientIP string) (Certificate, error) {
	request.Name = strings.TrimSpace(request.Name)
	if request.Name == "" || len(request.Name) > 100 {
		return Certificate{}, errors.New("证书名称长度无效")
	}
	if request.RenewBeforeDays < 1 || request.RenewBeforeDays > 365 {
		return Certificate{}, errors.New("提前续签天数必须在 1 到 365 之间")
	}
	if _, err := s.Get(ctx, id); err != nil {
		return Certificate{}, err
	}
	if err := s.store.UpdateCertificateSettings(ctx, id, request.Name, request.AutoRenewEnabled, request.RenewBeforeDays, request.CreateRenewedMarker); err != nil {
		return Certificate{}, err
	}
	_ = s.audit(ctx, id, "certificate.update", actor, clientIP, "succeeded", map[string]any{
		"auto_renew_enabled": request.AutoRenewEnabled, "renew_before_days": request.RenewBeforeDays,
		"create_renewed_marker": request.CreateRenewedMarker,
	})
	return s.Get(ctx, id)
}

func (s *Service) Revoke(ctx context.Context, id, actor, clientIP string) (Certificate, error) {
	value, err := s.Get(ctx, id)
	if err != nil {
		return Certificate{}, err
	}
	if value.Mode != ModeACME {
		return Certificate{}, errors.New("本地自签名证书不能通过 CA 撤销")
	}
	if s.acme == nil {
		return Certificate{}, errors.New("ACME 功能未启用")
	}
	lockValue, _ := s.locks.LoadOrStore(id, &sync.Mutex{})
	lock := lockValue.(*sync.Mutex)
	if !lock.TryLock() {
		return Certificate{}, ErrOperationRunning
	}
	defer lock.Unlock()
	job := &jobs.Run{CertificateID: id, JobType: "revoke", Status: "running"}
	if err := s.store.CreateJob(ctx, job); err != nil {
		return Certificate{}, err
	}
	if err := s.acme.Revoke(ctx, acmesh.RevokeRequest{PrimaryDomain: value.PrimaryDomain, KeyType: value.KeyType}); err != nil {
		_ = s.store.FinishJob(ctx, job.ID, "failed", acmeExitCode(err), "", safeError(err))
		_ = s.audit(ctx, id, "certificate.revoke", actor, clientIP, "failed", nil)
		return Certificate{}, err
	}
	if err := s.store.SetCertificateStatus(ctx, id, StatusRevoked); err != nil {
		return Certificate{}, err
	}
	_ = s.store.FinishJob(ctx, job.ID, "succeeded", 0, "", "")
	_ = s.audit(ctx, id, "certificate.revoke", actor, clientIP, "succeeded", nil)
	return s.Get(ctx, id)
}

func (s *Service) Delete(ctx context.Context, id string, deleteFiles bool, actor, clientIP string) error {
	value, err := s.Get(ctx, id)
	if err != nil {
		return err
	}
	lockValue, _ := s.locks.LoadOrStore(id, &sync.Mutex{})
	lock := lockValue.(*sync.Mutex)
	if !lock.TryLock() {
		return ErrOperationRunning
	}
	defer lock.Unlock()
	if deleteFiles {
		if _, err := s.publisher.Backup(value.OutputDirectory); err != nil {
			return err
		}
	}
	_ = s.audit(ctx, id, "certificate.delete", actor, clientIP, "succeeded", map[string]any{"delete_files": deleteFiles, "certificate_id": id})
	if err := s.store.DeleteCertificate(ctx, id); err != nil {
		return err
	}
	if deleteFiles {
		if err := s.publisher.Remove(value.OutputDirectory); err != nil {
			return fmt.Errorf("管理记录已删除，但证书目录清理失败: %w", err)
		}
	}
	s.locks.Delete(id)
	return nil
}

func (s *Service) Renew(ctx context.Context, id string, force bool, actor, clientIP string) (Certificate, error) {
	jobType, eventType := "renew", "certificate.renew"
	if force {
		jobType, eventType = "force_renew", "certificate.force_renew"
	}
	return s.issueExisting(ctx, id, force, jobType, eventType, actor, clientIP)
}

// Issue manually re-issues an existing certificate while preserving the
// create-immediately contract. It is intended for failed, expired, or
// explicitly requested refreshes and shares the same locking and publishing
// path as renewal.
func (s *Service) Issue(ctx context.Context, id, actor, clientIP string) (Certificate, error) {
	value, err := s.Get(ctx, id)
	if err != nil {
		return Certificate{}, err
	}
	if !manualIssueAllowed(value.Status) {
		return Certificate{}, errors.New("当前证书状态不允许重新签发")
	}
	return s.issueExisting(ctx, id, true, "issue", "certificate.issue", actor, clientIP)
}

func manualIssueAllowed(status Status) bool {
	switch status {
	case StatusPending, StatusFailed, StatusActive, StatusExpiring, StatusExpired:
		return true
	default:
		return false
	}
}

func (s *Service) issueExisting(ctx context.Context, id string, force bool, jobType, eventType, actor, clientIP string) (Certificate, error) {
	value, err := s.Get(ctx, id)
	if err != nil {
		return Certificate{}, err
	}
	lockValue, _ := s.locks.LoadOrStore(id, &sync.Mutex{})
	lock := lockValue.(*sync.Mutex)
	if !lock.TryLock() {
		return Certificate{}, ErrOperationRunning
	}
	defer lock.Unlock()
	if jobType == "issue" {
		if !manualIssueAllowed(value.Status) {
			return Certificate{}, errors.New("当前证书状态不允许重新签发")
		}
		return s.issueExistingCertificate(ctx, value, actor, clientIP)
	}
	if value.Status == StatusRevoked || value.Status == StatusDisabled {
		return Certificate{}, errors.New("当前证书状态不允许续签")
	}
	if err := s.store.SetCertificateStatus(ctx, id, StatusRenewing); err != nil {
		return Certificate{}, err
	}
	job := &jobs.Run{CertificateID: id, JobType: jobType, Status: "running"}
	if err := s.store.CreateJob(ctx, job); err != nil {
		return Certificate{}, err
	}
	var certPEM, chainPEM, fullchainPEM, privateKeyPEM []byte
	var metadataIssuer, metadataSerial, metadataFingerprint, keyAlgorithm, output string
	var notBefore, notAfter time.Time
	var commandExit int
	if value.Mode == ModeSelfSigned {
		result, renewErr := s.engine.Renew(ctx, selfsigned.Request{
			PrimaryDomain: value.PrimaryDomain, Domains: value.Domains, KeyType: value.KeyType, ValidDays: value.SelfSignedValidDays,
		})
		if renewErr != nil {
			return Certificate{}, s.failRenewal(ctx, value, job, exitCode(renewErr), "", renewErr, eventType, actor, clientIP)
		}
		if result == nil {
			return Certificate{}, s.failRenewal(ctx, value, job, -1, "", errors.New("自签名引擎未返回签发结果"), eventType, actor, clientIP)
		}
		certPEM, chainPEM, fullchainPEM, privateKeyPEM = result.CertificatePEM, result.CertificatePEM, result.CertificatePEM, result.PrivateKeyPEM
		metadataIssuer, metadataSerial, metadataFingerprint, keyAlgorithm = result.Metadata.Issuer.String(), result.Metadata.SerialNumber, result.Metadata.FingerprintSHA256, result.Metadata.KeyAlgorithm
		notBefore, notAfter, commandExit, output = result.Metadata.NotBefore, result.Metadata.NotAfter, result.ExitCode, result.OutputSummary
	} else if value.Mode == ModeACME {
		if s.acme == nil {
			return Certificate{}, s.failRenewal(ctx, value, job, -1, "", errors.New("ACME 功能未启用"), eventType, actor, clientIP)
		}
		var processValues credential.ProcessValues
		if value.ChallengeType == "dns-01" {
			if s.credentials == nil {
				return Certificate{}, s.failRenewal(ctx, value, job, -1, "", errors.New("DNS 凭据服务不可用"), eventType, actor, clientIP)
			}
			processValues, err = s.credentials.Resolve(ctx, value.DNSCredentialID)
			if err != nil {
				return Certificate{}, s.failRenewal(ctx, value, job, -1, "", err, eventType, actor, clientIP)
			}
		}
		result, renewErr := s.acme.Renew(ctx, acmesh.RenewRequest{
			CertificateID: id, PrimaryDomain: value.PrimaryDomain, KeyType: value.KeyType,
			Force: force, DNSVariables: processValues.Environment, CADirectory: value.CADirectoryURL,
		})
		if renewErr != nil {
			return Certificate{}, s.failRenewal(ctx, value, job, acmeExitCode(renewErr), "", renewErr, eventType, actor, clientIP)
		}
		if result == nil {
			return Certificate{}, s.failRenewal(ctx, value, job, -1, "", errors.New("ACME 引擎未返回签发结果"), eventType, actor, clientIP)
		}
		certPEM, chainPEM, fullchainPEM, privateKeyPEM = result.CertificatePEM, result.ChainPEM, result.FullchainPEM, result.PrivateKeyPEM
		metadataIssuer, metadataSerial, metadataFingerprint, keyAlgorithm = result.Metadata.Issuer.String(), result.Metadata.SerialNumber, result.Metadata.FingerprintSHA256, result.Metadata.KeyAlgorithm
		notBefore, notAfter, commandExit, output = result.Metadata.NotBefore, result.Metadata.NotAfter, result.ExitCode, result.OutputSummary
	} else {
		return Certificate{}, s.failRenewal(ctx, value, job, -1, "", errors.New("未知证书模式"), eventType, actor, clientIP)
	}
	metadataDocument, err := json.MarshalIndent(map[string]any{
		"certificate_id": value.ID, "name": value.Name, "mode": value.Mode, "primary_domain": value.PrimaryDomain,
		"domains": value.Domains, "issuer": metadataIssuer, "serial_number": metadataSerial,
		"not_before": notBefore, "not_after": notAfter, "fingerprint_sha256": metadataFingerprint,
		"key_algorithm": keyAlgorithm, "updated_at": s.now().UTC(),
	}, "", "  ")
	if err != nil {
		return Certificate{}, s.failRenewal(ctx, value, job, commandExit, output, err, eventType, actor, clientIP)
	}
	if _, err := s.publisher.Publish(value.OutputDirectory, certfiles.Payload{
		CertPEM: certPEM, ChainPEM: chainPEM, FullchainPEM: fullchainPEM, PrivateKeyPEM: privateKeyPEM,
		MetadataJSON: append(metadataDocument, '\n'), CreateMarker: value.CreateRenewedMarker,
	}); err != nil {
		return Certificate{}, s.failRenewal(ctx, value, job, commandExit, output, err, eventType, actor, clientIP)
	}
	value.Issuer, value.SerialNumber, value.FingerprintSHA256 = metadataIssuer, metadataSerial, metadataFingerprint
	value.NotBefore, value.NotAfter = timePointer(notBefore), timePointer(notAfter)
	if err := s.store.MarkCertificateRenewed(ctx, value); err != nil {
		return Certificate{}, err
	}
	_ = s.store.FinishJob(ctx, job.ID, "succeeded", commandExit, output, "")
	_ = s.audit(ctx, id, eventType, actor, clientIP, "succeeded", map[string]any{"mode": value.Mode})
	return s.Get(ctx, id)
}

func (s *Service) issueExistingCertificate(ctx context.Context, value Certificate, actor, clientIP string) (Certificate, error) {
	if value.Mode == ModeACME {
		if err := ValidateACMEDomains(value.PrimaryDomain, value.Domains); err != nil {
			return Certificate{}, err
		}
	}
	if err := s.store.SetCertificateStatus(ctx, value.ID, StatusIssuing); err != nil {
		return Certificate{}, err
	}
	job := &jobs.Run{CertificateID: value.ID, JobType: "issue", Status: "running"}
	if err := s.store.CreateJob(ctx, job); err != nil {
		_ = s.store.MarkCertificateFailed(ctx, value.ID, "无法创建任务记录")
		return Certificate{}, err
	}
	var certPEM, chainPEM, fullchainPEM, privateKeyPEM []byte
	var metadataIssuer, metadataSerial, metadataFingerprint, keyAlgorithm, output string
	var notBefore, notAfter time.Time
	var commandExit int
	if value.Mode == ModeSelfSigned {
		if s.engine == nil {
			return Certificate{}, s.failRenewal(ctx, value, job, -1, "", errors.New("自签名功能未启用"), "certificate.issue", actor, clientIP)
		}
		result, issueErr := s.engine.Issue(ctx, selfsigned.Request{PrimaryDomain: value.PrimaryDomain, Domains: value.Domains, KeyType: value.KeyType, ValidDays: value.SelfSignedValidDays})
		if issueErr != nil {
			return Certificate{}, s.failRenewal(ctx, value, job, exitCode(issueErr), "", issueErr, "certificate.issue", actor, clientIP)
		}
		if result == nil {
			return Certificate{}, s.failRenewal(ctx, value, job, -1, "", errors.New("自签名引擎未返回签发结果"), "certificate.issue", actor, clientIP)
		}
		certPEM, chainPEM, fullchainPEM, privateKeyPEM = result.CertificatePEM, result.CertificatePEM, result.CertificatePEM, result.PrivateKeyPEM
		metadataIssuer, metadataSerial, metadataFingerprint, keyAlgorithm = result.Metadata.Issuer.String(), result.Metadata.SerialNumber, result.Metadata.FingerprintSHA256, result.Metadata.KeyAlgorithm
		notBefore, notAfter, commandExit, output = result.Metadata.NotBefore, result.Metadata.NotAfter, result.ExitCode, result.OutputSummary
	} else if value.Mode == ModeACME {
		if s.acme == nil {
			return Certificate{}, s.failRenewal(ctx, value, job, -1, "", errors.New("ACME 功能未启用"), "certificate.issue", actor, clientIP)
		}
		var processValues credential.ProcessValues
		if value.ChallengeType == "dns-01" {
			if s.credentials == nil {
				return Certificate{}, s.failRenewal(ctx, value, job, -1, "", errors.New("DNS 凭据服务不可用"), "certificate.issue", actor, clientIP)
			}
			resolved, resolveErr := s.credentials.Resolve(ctx, value.DNSCredentialID)
			if resolveErr != nil {
				return Certificate{}, s.failRenewal(ctx, value, job, -1, "", resolveErr, "certificate.issue", actor, clientIP)
			}
			processValues = resolved
		} else if value.ChallengeType != "http-01" {
			return Certificate{}, s.failRenewal(ctx, value, job, -1, "", errors.New("仅支持 dns-01 或 http-01"), "certificate.issue", actor, clientIP)
		}
		result, issueErr := s.acme.Issue(ctx, acmesh.IssueRequest{
			CertificateID: value.ID, PrimaryDomain: value.PrimaryDomain, Domains: value.Domains, KeyType: value.KeyType,
			ChallengeType: value.ChallengeType, DNSProvider: processValues.ACMEDNSCode, DNSVariables: processValues.Environment,
			CADirectory: value.CADirectoryURL, Email: value.ACMEEmail,
		})
		if issueErr != nil {
			return Certificate{}, s.failRenewal(ctx, value, job, acmeExitCode(issueErr), "", issueErr, "certificate.issue", actor, clientIP)
		}
		if result == nil {
			return Certificate{}, s.failRenewal(ctx, value, job, -1, "", errors.New("ACME 引擎未返回签发结果"), "certificate.issue", actor, clientIP)
		}
		certPEM, chainPEM, fullchainPEM, privateKeyPEM = result.CertificatePEM, result.ChainPEM, result.FullchainPEM, result.PrivateKeyPEM
		metadataIssuer, metadataSerial, metadataFingerprint, keyAlgorithm = result.Metadata.Issuer.String(), result.Metadata.SerialNumber, result.Metadata.FingerprintSHA256, result.Metadata.KeyAlgorithm
		notBefore, notAfter, commandExit, output = result.Metadata.NotBefore, result.Metadata.NotAfter, result.ExitCode, result.OutputSummary
	} else {
		return Certificate{}, s.failRenewal(ctx, value, job, -1, "", errors.New("未知证书模式"), "certificate.issue", actor, clientIP)
	}
	metadataDocument, err := json.MarshalIndent(map[string]any{
		"certificate_id": value.ID, "name": value.Name, "mode": value.Mode, "primary_domain": value.PrimaryDomain,
		"domains": value.Domains, "issuer": metadataIssuer, "serial_number": metadataSerial,
		"not_before": notBefore, "not_after": notAfter, "fingerprint_sha256": metadataFingerprint,
		"key_algorithm": keyAlgorithm, "updated_at": s.now().UTC(),
	}, "", "  ")
	if err != nil {
		return Certificate{}, s.failRenewal(ctx, value, job, commandExit, output, err, "certificate.issue", actor, clientIP)
	}
	if _, err := s.publisher.Publish(value.OutputDirectory, certfiles.Payload{
		CertPEM: certPEM, ChainPEM: chainPEM, FullchainPEM: fullchainPEM, PrivateKeyPEM: privateKeyPEM,
		MetadataJSON: append(metadataDocument, '\n'), CreateMarker: value.CreateRenewedMarker,
	}); err != nil {
		return Certificate{}, s.failRenewal(ctx, value, job, commandExit, output, err, "certificate.issue", actor, clientIP)
	}
	value.Issuer, value.SerialNumber, value.FingerprintSHA256 = metadataIssuer, metadataSerial, metadataFingerprint
	value.NotBefore, value.NotAfter = timePointer(notBefore), timePointer(notAfter)
	if err := s.store.MarkCertificateIssued(ctx, value); err != nil {
		return Certificate{}, err
	}
	_ = s.store.FinishJob(ctx, job.ID, "succeeded", commandExit, output, "")
	_ = s.audit(ctx, value.ID, "certificate.issue", actor, clientIP, "succeeded", map[string]any{"mode": value.Mode})
	return s.Get(ctx, value.ID)
}

func (s *Service) RunRenewalScan(ctx context.Context, policy scheduler.Policy) error {
	values, err := s.List(ctx)
	if err != nil {
		return err
	}
	semaphore := make(chan struct{}, policy.MaxConcurrency)
	var wait sync.WaitGroup
	var errorsMu sync.Mutex
	var renewalErrors []error
	for _, item := range values {
		if !dueForRenewal(item, s.now()) {
			continue
		}
		item := item
		wait.Add(1)
		go func() {
			defer wait.Done()
			select {
			case semaphore <- struct{}{}:
				defer func() { <-semaphore }()
			case <-ctx.Done():
				return
			}
			var renewErr error
			for attempt := 0; attempt <= policy.RetryCount; attempt++ {
				_, renewErr = s.Renew(ctx, item.ID, false, "scheduler", "")
				if renewErr == nil || errors.Is(renewErr, ErrOperationRunning) || errors.Is(renewErr, context.Canceled) {
					break
				}
				if attempt < policy.RetryCount {
					timer := time.NewTimer(time.Duration(policy.RetryIntervalSeconds) * time.Second)
					select {
					case <-timer.C:
					case <-ctx.Done():
						timer.Stop()
						return
					}
				}
			}
			if renewErr != nil && !errors.Is(renewErr, ErrOperationRunning) {
				errorsMu.Lock()
				renewalErrors = append(renewalErrors, renewErr)
				errorsMu.Unlock()
			}
		}()
	}
	wait.Wait()
	return errors.Join(renewalErrors...)
}

func dueForRenewal(value Certificate, now time.Time) bool {
	if !value.AutoRenewEnabled || value.NotAfter == nil || value.Status == StatusDisabled || value.Status == StatusRevoked {
		return false
	}
	return !now.Before(value.NotAfter.Add(-time.Duration(value.RenewBeforeDays) * 24 * time.Hour))
}

func (s *Service) failRenewal(ctx context.Context, value Certificate, job *jobs.Run, exit int, output string, renewErr error, eventType, actor, clientIP string) error {
	message := safeError(renewErr)
	_ = s.store.FinishJob(ctx, job.ID, "failed", exit, output, message)
	_ = s.store.MarkCertificateFailed(ctx, value.ID, message)
	_ = s.audit(ctx, value.ID, eventType, actor, clientIP, "failed", map[string]any{"mode": value.Mode})
	return renewErr
}

func NewService(store Repository, engine selfsigned.Engine, publisher *certfiles.Publisher, acme acmesh.ACMEEngine, credentials interface {
	Resolve(context.Context, string) (credential.ProcessValues, error)
}) *Service {
	return &Service{store: store, engine: engine, publisher: publisher, acme: acme, credentials: credentials, now: time.Now}
}

func (s *Service) CreateACME(ctx context.Context, request CreateACMERequest, actor, clientIP string) (Certificate, error) {
	if s.acme == nil {
		return Certificate{}, errors.New("ACME 功能未启用")
	}
	request.Name = strings.TrimSpace(request.Name)
	if request.Name == "" || len(request.Name) > 100 {
		return Certificate{}, errors.New("证书名称长度必须在 1 到 100 之间")
	}
	primary, domains, err := NormalizeDomains(request.PrimaryDomain, request.SANs)
	if err != nil {
		return Certificate{}, err
	}
	if err := ValidateACMEDomains(primary, domains); err != nil {
		return Certificate{}, err
	}
	if request.OutputDirectory == "" {
		request.OutputDirectory = SafeDirectoryFromDomain(primary)
	}
	if err := certfiles.ValidateSafeDirectory(request.OutputDirectory); err != nil {
		return Certificate{}, err
	}
	if request.RenewBeforeDays < 1 || request.RenewBeforeDays > 90 {
		return Certificate{}, errors.New("ACME 提前续签天数必须在 1 到 90 之间")
	}
	if request.KeyType != "ec-256" && request.KeyType != "rsa-2048" && request.KeyType != "rsa-3072" {
		return Certificate{}, errors.New("不支持的 ACME 密钥类型")
	}
	var processValues credential.ProcessValues
	if request.ChallengeType == "dns-01" {
		if s.credentials == nil || request.DNSCredentialID == "" {
			return Certificate{}, errors.New("DNS-01 必须选择 DNS 凭据")
		}
		processValues, err = s.credentials.Resolve(ctx, request.DNSCredentialID)
		if err != nil {
			return Certificate{}, err
		}
	} else if request.ChallengeType != "http-01" {
		return Certificate{}, errors.New("仅支持 dns-01 或 http-01")
	}
	value := Certificate{
		Name: request.Name, Mode: ModeACME, PrimaryDomain: primary, Domains: domains, KeyType: request.KeyType,
		Status: StatusIssuing, OutputDirectory: request.OutputDirectory, AutoRenewEnabled: request.AutoRenewEnabled,
		RenewBeforeDays: request.RenewBeforeDays, ChallengeType: request.ChallengeType,
		DNSProvider: processValues.ACMEDNSCode, DNSCredentialID: request.DNSCredentialID,
		CADirectoryURL: request.CADirectoryURL, ACMEEmail: request.ACMEEmail, CreateRenewedMarker: request.CreateRenewedMarker,
	}
	if err := s.store.CreateCertificate(ctx, &value); err != nil {
		return Certificate{}, err
	}
	job := &jobs.Run{CertificateID: value.ID, JobType: "acme_issue", Status: "running"}
	if err := s.store.CreateJob(ctx, job); err != nil {
		_ = s.store.MarkCertificateFailed(ctx, value.ID, "无法创建任务记录")
		return Certificate{}, err
	}
	result, issueErr := s.acme.Issue(ctx, acmesh.IssueRequest{
		CertificateID: value.ID, PrimaryDomain: primary, Domains: domains, KeyType: request.KeyType,
		ChallengeType: request.ChallengeType, DNSProvider: processValues.ACMEDNSCode,
		DNSVariables: processValues.Environment, CADirectory: request.CADirectoryURL, Email: request.ACMEEmail,
	})
	if issueErr != nil {
		message := safeError(issueErr)
		_ = s.store.FinishJob(ctx, job.ID, "failed", acmeExitCode(issueErr), "", message)
		_ = s.store.MarkCertificateFailed(ctx, value.ID, message)
		_ = s.audit(ctx, value.ID, "certificate.create", actor, clientIP, "failed", map[string]any{"mode": ModeACME})
		return Certificate{}, issueErr
	}
	metadataDocument, err := json.MarshalIndent(map[string]any{
		"certificate_id": value.ID, "name": value.Name, "mode": value.Mode, "primary_domain": value.PrimaryDomain,
		"domains": value.Domains, "issuer": result.Metadata.Issuer.String(), "serial_number": result.Metadata.SerialNumber,
		"not_before": result.Metadata.NotBefore, "not_after": result.Metadata.NotAfter,
		"fingerprint_sha256": result.Metadata.FingerprintSHA256, "key_algorithm": result.Metadata.KeyAlgorithm,
		"updated_at": s.now().UTC(),
	}, "", "  ")
	if err != nil {
		return Certificate{}, err
	}
	if _, err := s.publisher.Publish(value.OutputDirectory, certfiles.Payload{
		CertPEM: result.CertificatePEM, ChainPEM: result.ChainPEM, FullchainPEM: result.FullchainPEM,
		PrivateKeyPEM: result.PrivateKeyPEM, MetadataJSON: append(metadataDocument, '\n'), CreateMarker: request.CreateRenewedMarker,
	}); err != nil {
		message := safeError(err)
		_ = s.store.FinishJob(ctx, job.ID, "failed", result.ExitCode, result.OutputSummary, message)
		_ = s.store.MarkCertificateFailed(ctx, value.ID, message)
		return Certificate{}, err
	}
	value.Issuer, value.SerialNumber = result.Metadata.Issuer.String(), result.Metadata.SerialNumber
	value.NotBefore, value.NotAfter = timePointer(result.Metadata.NotBefore), timePointer(result.Metadata.NotAfter)
	value.FingerprintSHA256 = result.Metadata.FingerprintSHA256
	if err := s.store.MarkCertificateIssued(ctx, value); err != nil {
		return Certificate{}, err
	}
	_ = s.store.FinishJob(ctx, job.ID, "succeeded", result.ExitCode, result.OutputSummary, "")
	_ = s.audit(ctx, value.ID, "certificate.create", actor, clientIP, "succeeded", map[string]any{"mode": ModeACME, "challenge_type": request.ChallengeType})
	return s.store.Certificate(ctx, value.ID)
}

func (s *Service) CreateSelfSigned(ctx context.Context, request CreateSelfSignedRequest, actor, clientIP string) (Certificate, error) {
	request.Name = strings.TrimSpace(request.Name)
	if request.Name == "" || len(request.Name) > 100 {
		return Certificate{}, errors.New("证书名称长度必须在 1 到 100 之间")
	}
	primary, domains, err := NormalizeDomains(request.PrimaryDomain, request.SANs)
	if err != nil {
		return Certificate{}, err
	}
	if request.OutputDirectory == "" {
		request.OutputDirectory = SafeDirectoryFromDomain(primary)
	}
	if err := certfiles.ValidateSafeDirectory(request.OutputDirectory); err != nil {
		return Certificate{}, err
	}
	if request.ValidDays < 1 || request.ValidDays > 3650 {
		return Certificate{}, errors.New("有效天数必须在 1 到 3650 之间")
	}
	if request.RenewBeforeDays < 1 || request.RenewBeforeDays >= request.ValidDays {
		return Certificate{}, errors.New("提前重新生成天数必须大于 0 且小于有效天数")
	}
	if request.KeyType != "ec-256" && request.KeyType != "rsa-2048" && request.KeyType != "rsa-3072" {
		return Certificate{}, errors.New("不支持的自签名密钥类型")
	}

	value := Certificate{
		Name: request.Name, Mode: ModeSelfSigned, PrimaryDomain: primary, Domains: domains,
		KeyType: request.KeyType, Status: StatusIssuing, OutputDirectory: request.OutputDirectory,
		AutoRenewEnabled: request.AutoRenewEnabled, RenewBeforeDays: request.RenewBeforeDays,
		SelfSignedValidDays: request.ValidDays, CreateRenewedMarker: request.CreateRenewedMarker,
	}
	if err := s.store.CreateCertificate(ctx, &value); err != nil {
		return Certificate{}, err
	}
	job := &jobs.Run{CertificateID: value.ID, JobType: "self_signed_issue", Status: "running"}
	if err := s.store.CreateJob(ctx, job); err != nil {
		_ = s.store.MarkCertificateFailed(ctx, value.ID, "无法创建任务记录")
		return Certificate{}, err
	}

	result, issueErr := s.engine.Issue(ctx, selfsigned.Request{
		PrimaryDomain: primary, Domains: domains, KeyType: request.KeyType, ValidDays: request.ValidDays,
	})
	if issueErr != nil {
		message := safeError(issueErr)
		_ = s.store.FinishJob(ctx, job.ID, "failed", exitCode(issueErr), "", message)
		_ = s.store.MarkCertificateFailed(ctx, value.ID, message)
		_ = s.audit(ctx, value.ID, "certificate.create", actor, clientIP, "failed", map[string]any{"mode": ModeSelfSigned})
		return Certificate{}, issueErr
	}

	metadataDocument, err := json.MarshalIndent(map[string]any{
		"certificate_id": value.ID, "name": value.Name, "mode": value.Mode,
		"primary_domain": value.PrimaryDomain, "domains": value.Domains, "issuer": result.Metadata.Issuer.String(),
		"serial_number": result.Metadata.SerialNumber, "not_before": result.Metadata.NotBefore,
		"not_after": result.Metadata.NotAfter, "fingerprint_sha256": result.Metadata.FingerprintSHA256,
		"key_algorithm": result.Metadata.KeyAlgorithm, "updated_at": s.now().UTC(),
	}, "", "  ")
	if err != nil {
		return Certificate{}, err
	}
	_, err = s.publisher.Publish(value.OutputDirectory, certfiles.Payload{
		CertPEM: result.CertificatePEM, ChainPEM: result.CertificatePEM, FullchainPEM: result.CertificatePEM,
		PrivateKeyPEM: result.PrivateKeyPEM, MetadataJSON: append(metadataDocument, '\n'),
		CreateMarker: request.CreateRenewedMarker,
	})
	if err != nil {
		message := safeError(err)
		_ = s.store.FinishJob(ctx, job.ID, "failed", result.ExitCode, result.OutputSummary, message)
		_ = s.store.MarkCertificateFailed(ctx, value.ID, message)
		return Certificate{}, err
	}

	value.Issuer = result.Metadata.Issuer.String()
	value.SerialNumber = result.Metadata.SerialNumber
	value.NotBefore = timePointer(result.Metadata.NotBefore)
	value.NotAfter = timePointer(result.Metadata.NotAfter)
	value.FingerprintSHA256 = result.Metadata.FingerprintSHA256
	if err := s.store.MarkCertificateIssued(ctx, value); err != nil {
		return Certificate{}, err
	}
	_ = s.store.FinishJob(ctx, job.ID, "succeeded", result.ExitCode, result.OutputSummary, "")
	_ = s.audit(ctx, value.ID, "certificate.create", actor, clientIP, "succeeded", map[string]any{
		"mode": ModeSelfSigned, "domain_count": len(domains), "key_type": value.KeyType,
	})
	return s.store.Certificate(ctx, value.ID)
}

func (s *Service) List(ctx context.Context) ([]Certificate, error) {
	return s.store.Certificates(ctx)
}

func (s *Service) Get(ctx context.Context, id string) (Certificate, error) {
	value, err := s.store.Certificate(ctx, id)
	return value, err
}

func (s *Service) ReadFile(ctx context.Context, id, fileName string) ([]byte, error) {
	value, err := s.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	content, _, err := s.publisher.Read(value.OutputDirectory, fileName)
	return content, err
}

func (s *Service) AuditFileAccess(ctx context.Context, id, eventType, actor, clientIP string) error {
	return s.audit(ctx, id, eventType, actor, clientIP, "succeeded", nil)
}

func (s *Service) ContainerPath(value Certificate, fileName string) string {
	return filepath.ToSlash(filepath.Join("/certs", value.OutputDirectory, fileName))
}

func (s *Service) audit(ctx context.Context, certificateID, eventType, actor, clientIP, result string, detail map[string]any) error {
	return s.store.CreateAuditEvent(ctx, &audit.Event{
		CertificateID: certificateID, EventType: eventType, Actor: actor, ClientIP: clientIP, Result: result, Detail: detail,
	})
}

func safeError(err error) string {
	value := err.Error()
	if len(value) > 2048 {
		value = value[:2048]
	}
	return value
}

func exitCode(err error) int {
	var commandErr *selfsigned.CommandError
	if errors.As(err, &commandErr) {
		return commandErr.ExitCode
	}
	return -1
}

func acmeExitCode(err error) int {
	var commandErr *acmesh.CommandError
	if errors.As(err, &commandErr) {
		return commandErr.ExitCode
	}
	return -1
}

func timePointer(value time.Time) *time.Time {
	return &value
}

func (s *Service) String() string {
	return fmt.Sprintf("certificate.Service{%p}", s)
}
