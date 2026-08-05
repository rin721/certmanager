// Package sqlite 提供项目核心元数据的 SQLite 持久化实现。
package sqlite

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pressly/goose/v3"
	"github.com/rin721/certmate/internal/audit"
	"github.com/rin721/certmate/internal/certificate"
	"github.com/rin721/certmate/internal/credential"
	"github.com/rin721/certmate/internal/jobs"
	"github.com/rin721/certmate/internal/scheduler"
	"github.com/rin721/certmate/migrations"
	_ "modernc.org/sqlite"
)

const timestampLayout = time.RFC3339Nano

type Store struct {
	db  *sql.DB
	now func() time.Time
}

func Open(ctx context.Context, dataDir string) (*Store, error) {
	if err := os.MkdirAll(dataDir, 0o750); err != nil {
		return nil, fmt.Errorf("创建数据目录: %w", err)
	}
	databasePath := filepath.Join(dataDir, "app.db")
	uriPath := filepath.ToSlash(databasePath)
	if filepath.VolumeName(databasePath) != "" && !strings.HasPrefix(uriPath, "/") {
		uriPath = "/" + uriPath
	}
	dsnURL := &url.URL{Scheme: "file", Path: uriPath}
	query := dsnURL.Query()
	query.Add("_pragma", "foreign_keys(1)")
	query.Add("_pragma", "journal_mode(WAL)")
	query.Add("_pragma", "busy_timeout(5000)")
	dsnURL.RawQuery = query.Encode()

	db, err := sql.Open("sqlite", dsnURL.String())
	if err != nil {
		return nil, fmt.Errorf("打开 SQLite: %w", err)
	}
	db.SetMaxOpenConns(4)
	db.SetMaxIdleConns(4)
	db.SetConnMaxLifetime(time.Hour)
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("连接 SQLite: %w", err)
	}
	return &Store{db: db, now: time.Now}, nil
}

func (s *Store) Migrate(ctx context.Context) error {
	goose.SetBaseFS(migrations.FS)
	if err := goose.SetDialect("sqlite3"); err != nil {
		return fmt.Errorf("设置 goose 方言: %w", err)
	}
	if err := goose.UpContext(ctx, s.db, "."); err != nil {
		return fmt.Errorf("执行数据库迁移: %w", err)
	}
	return nil
}

func (s *Store) PingContext(ctx context.Context) error {
	return s.db.PingContext(ctx)
}

func (s *Store) Close() error {
	return s.db.Close()
}

func (s *Store) MarkInterruptedJobs(ctx context.Context) (int64, error) {
	now := s.now().UTC().Format(timestampLayout)
	result, err := s.db.ExecContext(ctx, `
		UPDATE job_runs
		SET status = 'interrupted', finished_at = ?,
			error_message = CASE WHEN error_message = '' THEN '应用重启导致任务中断' ELSE error_message END
		WHERE status = 'running'`, now)
	if err != nil {
		return 0, fmt.Errorf("恢复遗留任务: %w", err)
	}
	return result.RowsAffected()
}

func (s *Store) RenewalPolicy(ctx context.Context) (scheduler.Policy, error) {
	var policy scheduler.Policy
	var enabled int
	var updatedAt string
	err := s.db.QueryRowContext(ctx, `
		SELECT enabled, cron_expression, timezone, max_concurrency, retry_count,
			retry_interval_seconds, updated_at
		FROM renewal_policies WHERE id = 1`).Scan(
		&enabled, &policy.CronExpression, &policy.Timezone, &policy.MaxConcurrency,
		&policy.RetryCount, &policy.RetryIntervalSeconds, &updatedAt,
	)
	if err != nil {
		return scheduler.Policy{}, fmt.Errorf("读取续签策略: %w", err)
	}
	policy.Enabled = enabled == 1
	policy.UpdatedAt, err = time.Parse(timestampLayout, updatedAt)
	if err != nil {
		return scheduler.Policy{}, fmt.Errorf("解析续签策略更新时间: %w", err)
	}
	return policy, nil
}

func (s *Store) UpdateRenewalPolicy(ctx context.Context, policy scheduler.Policy) error {
	policy.UpdatedAt = s.now().UTC()
	_, err := s.db.ExecContext(ctx, `
		UPDATE renewal_policies SET enabled = ?, cron_expression = ?, timezone = ?, max_concurrency = ?,
			retry_count = ?, retry_interval_seconds = ?, updated_at = ? WHERE id = 1`,
		boolInt(policy.Enabled), policy.CronExpression, policy.Timezone, policy.MaxConcurrency,
		policy.RetryCount, policy.RetryIntervalSeconds, policy.UpdatedAt.Format(timestampLayout),
	)
	if err != nil {
		return fmt.Errorf("更新续签策略: %w", err)
	}
	return nil
}

func (s *Store) CreateJob(ctx context.Context, run *jobs.Run) error {
	if run.ID == "" {
		run.ID = newID()
	}
	if run.StartedAt.IsZero() {
		run.StartedAt = s.now().UTC()
	}
	if run.Attempt == 0 {
		run.Attempt = 1
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO job_runs (
			id, certificate_id, job_type, status, started_at, finished_at, exit_code,
			sanitized_output, error_message, attempt, created_at
		) VALUES (?, NULLIF(?, ''), ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		run.ID, run.CertificateID, run.JobType, run.Status, run.StartedAt.UTC().Format(timestampLayout),
		nullTime(run.FinishedAt), run.ExitCode, run.SanitizedOutput, run.ErrorMessage, run.Attempt,
		s.now().UTC().Format(timestampLayout),
	)
	if err != nil {
		return fmt.Errorf("创建任务记录: %w", err)
	}
	return nil
}

func (s *Store) FinishJob(ctx context.Context, id, status string, exitCode int, output, errorMessage string) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE job_runs SET status = ?, finished_at = ?, exit_code = ?, sanitized_output = ?, error_message = ?
		WHERE id = ?`, status, s.now().UTC().Format(timestampLayout), exitCode, output, errorMessage, id)
	if err != nil {
		return fmt.Errorf("完成任务记录: %w", err)
	}
	return nil
}

func (s *Store) Jobs(ctx context.Context, query jobs.Query) ([]jobs.Run, error) {
	where := []string{"1 = 1"}
	arguments := make([]any, 0, 4)
	if query.CertificateID != "" {
		where = append(where, "certificate_id = ?")
		arguments = append(arguments, query.CertificateID)
	}
	if query.Status != "" {
		where = append(where, "status = ?")
		arguments = append(arguments, query.Status)
	}
	if query.JobType != "" {
		where = append(where, "job_type = ?")
		arguments = append(arguments, query.JobType)
	}
	if query.Since != nil {
		where = append(where, "started_at >= ?")
		arguments = append(arguments, query.Since.UTC().Format(timestampLayout))
	}
	limit := query.Limit
	if limit < 1 || limit > 200 {
		limit = 100
	}
	arguments = append(arguments, limit)
	rows, err := s.db.QueryContext(ctx, `SELECT id, COALESCE(certificate_id, ''), job_type, status,
		started_at, finished_at, exit_code, sanitized_output, error_message, attempt
		FROM job_runs WHERE `+strings.Join(where, " AND ")+` ORDER BY started_at DESC LIMIT ?`, arguments...)
	if err != nil {
		return nil, fmt.Errorf("查询任务记录: %w", err)
	}
	defer rows.Close()
	values := make([]jobs.Run, 0)
	for rows.Next() {
		value, scanErr := scanJob(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		values = append(values, value)
	}
	return values, rows.Err()
}

func (s *Store) Job(ctx context.Context, id string) (jobs.Run, error) {
	value, err := scanJob(s.db.QueryRowContext(ctx, `SELECT id, COALESCE(certificate_id, ''), job_type, status,
		started_at, finished_at, exit_code, sanitized_output, error_message, attempt FROM job_runs WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return jobs.Run{}, sql.ErrNoRows
	}
	return value, err
}

func (s *Store) CreateCertificate(ctx context.Context, value *certificate.Certificate) error {
	if value.ID == "" {
		value.ID = newID()
	}
	if value.CreatedAt.IsZero() {
		value.CreatedAt = s.now().UTC()
	}
	value.UpdatedAt = value.CreatedAt
	domains, err := json.Marshal(value.Domains)
	if err != nil {
		return fmt.Errorf("编码证书域名: %w", err)
	}
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO certificates (
			id, name, mode, primary_domain, domains_json, key_type, status, output_directory,
			auto_renew_enabled, renew_before_days, challenge_type, dns_provider, dns_credential_id,
			ca_directory_url, acme_email, self_signed_valid_days, create_renewed_marker,
			created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULLIF(?, ''), NULLIF(?, ''), NULLIF(?, ''),
			NULLIF(?, ''), NULLIF(?, ''), NULLIF(?, 0), ?, ?, ?)`,
		value.ID, value.Name, value.Mode, value.PrimaryDomain, string(domains), value.KeyType, value.Status,
		value.OutputDirectory, boolInt(value.AutoRenewEnabled), value.RenewBeforeDays, value.ChallengeType,
		value.DNSProvider, value.DNSCredentialID, value.CADirectoryURL, value.ACMEEmail,
		value.SelfSignedValidDays, boolInt(value.CreateRenewedMarker),
		value.CreatedAt.Format(timestampLayout), value.UpdatedAt.Format(timestampLayout),
	)
	if err != nil {
		return fmt.Errorf("创建证书记录: %w", err)
	}
	return nil
}

func (s *Store) Certificate(ctx context.Context, id string) (certificate.Certificate, error) {
	row := s.db.QueryRowContext(ctx, certificateSelect+` WHERE id = ?`, id)
	value, err := scanCertificate(row)
	if errors.Is(err, sql.ErrNoRows) {
		return certificate.Certificate{}, certificate.ErrNotFound
	}
	if err != nil {
		return certificate.Certificate{}, err
	}
	return value, nil
}

func (s *Store) Certificates(ctx context.Context) ([]certificate.Certificate, error) {
	rows, err := s.db.QueryContext(ctx, certificateSelect+` ORDER BY not_after IS NULL, not_after ASC, created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("查询证书列表: %w", err)
	}
	defer rows.Close()
	values := make([]certificate.Certificate, 0)
	for rows.Next() {
		value, err := scanCertificate(rows)
		if err != nil {
			return nil, err
		}
		values = append(values, value)
	}
	return values, rows.Err()
}

func (s *Store) MarkCertificateIssued(ctx context.Context, value certificate.Certificate) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE certificates SET status = 'active', issuer = ?, serial_number = ?, not_before = ?, not_after = ?,
			fingerprint_sha256 = ?, updated_at = ?, last_issued_at = ?, last_error = ''
		WHERE id = ?`, value.Issuer, value.SerialNumber, nullTime(value.NotBefore), nullTime(value.NotAfter),
		value.FingerprintSHA256, s.now().UTC().Format(timestampLayout), s.now().UTC().Format(timestampLayout), value.ID)
	if err != nil {
		return fmt.Errorf("更新证书签发状态: %w", err)
	}
	return nil
}

func (s *Store) MarkCertificateRenewed(ctx context.Context, value certificate.Certificate) error {
	now := s.now().UTC().Format(timestampLayout)
	_, err := s.db.ExecContext(ctx, `
		UPDATE certificates SET status = 'active', issuer = ?, serial_number = ?, not_before = ?, not_after = ?,
			fingerprint_sha256 = ?, updated_at = ?, last_renewed_at = ?, last_error = '' WHERE id = ?`,
		value.Issuer, value.SerialNumber, nullTime(value.NotBefore), nullTime(value.NotAfter),
		value.FingerprintSHA256, now, now, value.ID,
	)
	if err != nil {
		return fmt.Errorf("更新证书续签状态: %w", err)
	}
	return nil
}

func (s *Store) MarkCertificateFailed(ctx context.Context, id, message string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE certificates SET status = 'failed', last_error = ?, updated_at = ? WHERE id = ?`,
		message, s.now().UTC().Format(timestampLayout), id)
	return err
}

func (s *Store) SetCertificateStatus(ctx context.Context, id string, status certificate.Status) error {
	_, err := s.db.ExecContext(ctx, `UPDATE certificates SET status = ?, updated_at = ? WHERE id = ?`, status, s.now().UTC().Format(timestampLayout), id)
	return err
}

func (s *Store) UpdateCertificateSettings(ctx context.Context, id, name string, autoRenewEnabled bool, renewBeforeDays int, createRenewedMarker bool) error {
	result, err := s.db.ExecContext(ctx, `UPDATE certificates SET name = ?, auto_renew_enabled = ?, renew_before_days = ?,
		create_renewed_marker = ?, updated_at = ? WHERE id = ?`, name, autoRenewEnabled, renewBeforeDays,
		createRenewedMarker, s.now().UTC().Format(timestampLayout), id)
	if err != nil {
		return fmt.Errorf("更新证书设置: %w", err)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count == 0 {
		return certificate.ErrNotFound
	}
	return nil
}

func (s *Store) DeleteCertificate(ctx context.Context, id string) error {
	result, err := s.db.ExecContext(ctx, `DELETE FROM certificates WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("删除证书记录: %w", err)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count == 0 {
		return certificate.ErrNotFound
	}
	return nil
}

func (s *Store) CreateAuditEvent(ctx context.Context, event *audit.Event) error {
	if event.ID == "" {
		event.ID = newID()
	}
	if event.CreatedAt.IsZero() {
		event.CreatedAt = s.now().UTC()
	}
	detail, err := json.Marshal(event.Detail)
	if err != nil {
		return fmt.Errorf("编码审计详情: %w", err)
	}
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO audit_events (
			id, certificate_id, event_type, actor, client_ip, result, detail_json, created_at
		) VALUES (?, NULLIF(?, ''), ?, ?, ?, ?, ?, ?)`,
		event.ID, event.CertificateID, event.EventType, event.Actor, event.ClientIP,
		event.Result, string(detail), event.CreatedAt.UTC().Format(timestampLayout),
	)
	if err != nil {
		return fmt.Errorf("创建审计记录: %w", err)
	}
	return nil
}

func (s *Store) AuditEvents(ctx context.Context, query audit.Query) ([]audit.Event, error) {
	where := []string{"1 = 1"}
	arguments := make([]any, 0, 4)
	if query.CertificateID != "" {
		where = append(where, "certificate_id = ?")
		arguments = append(arguments, query.CertificateID)
	}
	if query.EventType != "" {
		where = append(where, "event_type = ?")
		arguments = append(arguments, query.EventType)
	}
	if query.Since != nil {
		where = append(where, "created_at >= ?")
		arguments = append(arguments, query.Since.UTC().Format(timestampLayout))
	}
	limit := query.Limit
	if limit < 1 || limit > 200 {
		limit = 100
	}
	arguments = append(arguments, limit)
	rows, err := s.db.QueryContext(ctx, `SELECT id, COALESCE(certificate_id, ''), event_type, actor,
		client_ip, result, detail_json, created_at FROM audit_events WHERE `+strings.Join(where, " AND ")+` ORDER BY created_at DESC LIMIT ?`, arguments...)
	if err != nil {
		return nil, fmt.Errorf("查询审计记录: %w", err)
	}
	defer rows.Close()
	values := make([]audit.Event, 0)
	for rows.Next() {
		value, scanErr := scanAuditEvent(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		values = append(values, value)
	}
	return values, rows.Err()
}

func (s *Store) CreateDNSCredential(ctx context.Context, value *credential.Credential, encrypted []byte) error {
	if value.ID == "" {
		value.ID = newID()
	}
	if value.CreatedAt.IsZero() {
		value.CreatedAt = s.now().UTC()
	}
	value.UpdatedAt = value.CreatedAt
	environmentRefs, err := json.Marshal(value.EnvironmentRefs)
	if err != nil {
		return err
	}
	maskedFields, err := json.Marshal(value.MaskedFields)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO dns_credentials (
			id, name, provider, acme_dns_code, source_mode, encrypted_values,
			environment_refs_json, masked_fields_json, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		value.ID, value.Name, value.Provider, value.ACMEDNSCode, value.SourceMode, nullableBytes(encrypted),
		nullableJSON(environmentRefs), string(maskedFields), value.CreatedAt.Format(timestampLayout), value.UpdatedAt.Format(timestampLayout),
	)
	if err != nil {
		return fmt.Errorf("创建 DNS 凭据: %w", err)
	}
	return nil
}

func (s *Store) UpdateDNSCredential(ctx context.Context, value *credential.Credential, encrypted []byte) error {
	environmentRefs, err := json.Marshal(value.EnvironmentRefs)
	if err != nil {
		return err
	}
	maskedFields, err := json.Marshal(value.MaskedFields)
	if err != nil {
		return err
	}
	value.UpdatedAt = s.now().UTC()
	result, err := s.db.ExecContext(ctx, `UPDATE dns_credentials SET
		name = ?, provider = ?, acme_dns_code = ?, source_mode = ?, encrypted_values = ?,
		environment_refs_json = ?, masked_fields_json = ?, updated_at = ? WHERE id = ?`,
		value.Name, value.Provider, value.ACMEDNSCode, value.SourceMode, nullableBytes(encrypted),
		nullableJSON(environmentRefs), string(maskedFields), value.UpdatedAt.Format(timestampLayout), value.ID)
	if err != nil {
		return fmt.Errorf("更新 DNS 凭据: %w", err)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count == 0 {
		return credential.ErrNotFound
	}
	stored, _, err := s.DNSCredential(ctx, value.ID)
	if err != nil {
		return err
	}
	*value = stored
	return nil
}

func (s *Store) DNSCredentials(ctx context.Context) ([]credential.Credential, error) {
	rows, err := s.db.QueryContext(ctx, dnsCredentialSelect+` ORDER BY name ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	values := make([]credential.Credential, 0)
	for rows.Next() {
		value, _, err := scanDNSCredential(rows)
		if err != nil {
			return nil, err
		}
		values = append(values, value)
	}
	return values, rows.Err()
}

func (s *Store) DNSCredential(ctx context.Context, id string) (credential.Credential, []byte, error) {
	value, encrypted, err := scanDNSCredential(s.db.QueryRowContext(ctx, dnsCredentialSelect+` WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return credential.Credential{}, nil, credential.ErrNotFound
	}
	return value, encrypted, err
}

func (s *Store) DeleteDNSCredential(ctx context.Context, id string) error {
	result, err := s.db.ExecContext(ctx, `DELETE FROM dns_credentials WHERE id = ?`, id)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count == 0 {
		return credential.ErrNotFound
	}
	return nil
}

func newID() string {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		panic(fmt.Errorf("生成随机 ID: %w", err))
	}
	return hex.EncodeToString(value[:])
}

func nullTime(value *time.Time) any {
	if value == nil {
		return nil
	}
	return value.UTC().Format(timestampLayout)
}

const certificateSelect = `SELECT
	id, name, mode, primary_domain, domains_json, key_type, status, output_directory,
	issuer, serial_number, not_before, not_after, fingerprint_sha256, auto_renew_enabled,
	renew_before_days, challenge_type, dns_provider, dns_credential_id, ca_directory_url,
	acme_email, self_signed_valid_days, create_renewed_marker, created_at, updated_at,
	last_issued_at, last_renewed_at, next_check_at, last_error
	FROM certificates`

type scanner interface {
	Scan(dest ...any) error
}

func scanJob(row scanner) (jobs.Run, error) {
	var value jobs.Run
	var startedAt string
	var finishedAt sql.NullString
	var exitCode sql.NullInt64
	if err := row.Scan(&value.ID, &value.CertificateID, &value.JobType, &value.Status, &startedAt,
		&finishedAt, &exitCode, &value.SanitizedOutput, &value.ErrorMessage, &value.Attempt); err != nil {
		return jobs.Run{}, err
	}
	var err error
	value.StartedAt, err = time.Parse(timestampLayout, startedAt)
	if err != nil {
		return jobs.Run{}, err
	}
	if finishedAt.Valid {
		parsed, parseErr := time.Parse(timestampLayout, finishedAt.String)
		if parseErr != nil {
			return jobs.Run{}, parseErr
		}
		value.FinishedAt = &parsed
	}
	if exitCode.Valid {
		exit := int(exitCode.Int64)
		value.ExitCode = &exit
	}
	return value, nil
}

func scanAuditEvent(row scanner) (audit.Event, error) {
	var value audit.Event
	var detail, createdAt string
	if err := row.Scan(&value.ID, &value.CertificateID, &value.EventType, &value.Actor,
		&value.ClientIP, &value.Result, &detail, &createdAt); err != nil {
		return audit.Event{}, err
	}
	if err := json.Unmarshal([]byte(detail), &value.Detail); err != nil {
		return audit.Event{}, err
	}
	var err error
	value.CreatedAt, err = time.Parse(timestampLayout, createdAt)
	return value, err
}

func scanCertificate(row scanner) (certificate.Certificate, error) {
	var value certificate.Certificate
	var domains string
	var mode, status string
	var autoRenew, marker int
	var notBefore, notAfter, challenge, provider, credentialID, caURL, email, validDays sql.NullString
	var createdAt, updatedAt string
	var lastIssued, lastRenewed, nextCheck sql.NullString
	err := row.Scan(
		&value.ID, &value.Name, &mode, &value.PrimaryDomain, &domains, &value.KeyType, &status,
		&value.OutputDirectory, &value.Issuer, &value.SerialNumber, &notBefore, &notAfter,
		&value.FingerprintSHA256, &autoRenew, &value.RenewBeforeDays, &challenge, &provider,
		&credentialID, &caURL, &email, &validDays, &marker, &createdAt, &updatedAt,
		&lastIssued, &lastRenewed, &nextCheck, &value.LastError,
	)
	if err != nil {
		return certificate.Certificate{}, err
	}
	value.Mode = certificate.Mode(mode)
	value.Status = certificate.Status(status)
	value.AutoRenewEnabled = autoRenew == 1
	value.CreateRenewedMarker = marker == 1
	value.ChallengeType, value.DNSProvider, value.DNSCredentialID = challenge.String, provider.String, credentialID.String
	value.CADirectoryURL, value.ACMEEmail = caURL.String, email.String
	if validDays.Valid {
		_, _ = fmt.Sscan(validDays.String, &value.SelfSignedValidDays)
	}
	if err := json.Unmarshal([]byte(domains), &value.Domains); err != nil {
		return certificate.Certificate{}, fmt.Errorf("解析证书域名: %w", err)
	}
	var parseErr error
	if value.CreatedAt, parseErr = time.Parse(timestampLayout, createdAt); parseErr != nil {
		return certificate.Certificate{}, parseErr
	}
	if value.UpdatedAt, parseErr = time.Parse(timestampLayout, updatedAt); parseErr != nil {
		return certificate.Certificate{}, parseErr
	}
	for source, target := range map[*sql.NullString]**time.Time{
		&notBefore: &value.NotBefore, &notAfter: &value.NotAfter, &lastIssued: &value.LastIssuedAt,
		&lastRenewed: &value.LastRenewedAt, &nextCheck: &value.NextCheckAt,
	} {
		if source.Valid {
			parsed, err := time.Parse(timestampLayout, source.String)
			if err != nil {
				return certificate.Certificate{}, err
			}
			*target = &parsed
		}
	}
	return value, nil
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

const dnsCredentialSelect = `SELECT
	id, name, provider, acme_dns_code, source_mode, encrypted_values,
	environment_refs_json, masked_fields_json, created_at, updated_at
	FROM dns_credentials`

func scanDNSCredential(row scanner) (credential.Credential, []byte, error) {
	var value credential.Credential
	var encrypted []byte
	var environmentRefs, maskedFields sql.NullString
	var createdAt, updatedAt string
	if err := row.Scan(&value.ID, &value.Name, &value.Provider, &value.ACMEDNSCode, &value.SourceMode,
		&encrypted, &environmentRefs, &maskedFields, &createdAt, &updatedAt); err != nil {
		return credential.Credential{}, nil, err
	}
	if environmentRefs.Valid && environmentRefs.String != "" {
		if err := json.Unmarshal([]byte(environmentRefs.String), &value.EnvironmentRefs); err != nil {
			return credential.Credential{}, nil, err
		}
	}
	if maskedFields.Valid {
		if err := json.Unmarshal([]byte(maskedFields.String), &value.MaskedFields); err != nil {
			return credential.Credential{}, nil, err
		}
	}
	var err error
	value.CreatedAt, err = time.Parse(timestampLayout, createdAt)
	if err != nil {
		return credential.Credential{}, nil, err
	}
	value.UpdatedAt, err = time.Parse(timestampLayout, updatedAt)
	return value, encrypted, err
}

func nullableBytes(value []byte) any {
	if len(value) == 0 {
		return nil
	}
	return value
}

func nullableJSON(value []byte) any {
	if string(value) == "null" || string(value) == "{}" {
		return nil
	}
	return string(value)
}
