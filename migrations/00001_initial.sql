-- +goose Up
CREATE TABLE certificates (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    mode TEXT NOT NULL CHECK (mode IN ('acme', 'self_signed')),
    primary_domain TEXT NOT NULL,
    domains_json TEXT NOT NULL,
    key_type TEXT NOT NULL,
    status TEXT NOT NULL,
    output_directory TEXT NOT NULL UNIQUE,
    issuer TEXT NOT NULL DEFAULT '',
    serial_number TEXT NOT NULL DEFAULT '',
    not_before TEXT,
    not_after TEXT,
    fingerprint_sha256 TEXT NOT NULL DEFAULT '',
    auto_renew_enabled INTEGER NOT NULL DEFAULT 1 CHECK (auto_renew_enabled IN (0, 1)),
    renew_before_days INTEGER NOT NULL DEFAULT 30 CHECK (renew_before_days BETWEEN 1 AND 365),
    challenge_type TEXT,
    dns_provider TEXT,
    dns_credential_id TEXT,
    ca_directory_url TEXT,
    acme_email TEXT,
    self_signed_valid_days INTEGER,
    create_renewed_marker INTEGER NOT NULL DEFAULT 1 CHECK (create_renewed_marker IN (0, 1)),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    last_issued_at TEXT,
    last_renewed_at TEXT,
    next_check_at TEXT,
    last_error TEXT NOT NULL DEFAULT '',
    FOREIGN KEY (dns_credential_id) REFERENCES dns_credentials(id) ON DELETE SET NULL
);

CREATE INDEX certificates_status_idx ON certificates(status);
CREATE INDEX certificates_not_after_idx ON certificates(not_after);
CREATE INDEX certificates_mode_idx ON certificates(mode);

CREATE TABLE dns_credentials (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    provider TEXT NOT NULL,
    source_mode TEXT NOT NULL DEFAULT 'encrypted' CHECK (source_mode IN ('encrypted', 'environment')),
    encrypted_values BLOB,
    environment_refs_json TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE renewal_policies (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    enabled INTEGER NOT NULL CHECK (enabled IN (0, 1)),
    cron_expression TEXT NOT NULL,
    timezone TEXT NOT NULL,
    max_concurrency INTEGER NOT NULL CHECK (max_concurrency BETWEEN 1 AND 16),
    retry_count INTEGER NOT NULL CHECK (retry_count BETWEEN 0 AND 10),
    retry_interval_seconds INTEGER NOT NULL CHECK (retry_interval_seconds BETWEEN 1 AND 86400),
    updated_at TEXT NOT NULL
);

INSERT INTO renewal_policies (
    id, enabled, cron_expression, timezone, max_concurrency, retry_count, retry_interval_seconds, updated_at
) VALUES (1, 1, '0 3 * * *', 'Asia/Shanghai', 2, 3, 300, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'));

CREATE TABLE job_runs (
    id TEXT PRIMARY KEY,
    certificate_id TEXT,
    job_type TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending', 'running', 'succeeded', 'failed', 'interrupted', 'cancelled')),
    started_at TEXT NOT NULL,
    finished_at TEXT,
    exit_code INTEGER,
    sanitized_output TEXT NOT NULL DEFAULT '',
    error_message TEXT NOT NULL DEFAULT '',
    attempt INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    FOREIGN KEY (certificate_id) REFERENCES certificates(id) ON DELETE SET NULL
);

CREATE INDEX job_runs_certificate_idx ON job_runs(certificate_id, started_at DESC);
CREATE INDEX job_runs_status_idx ON job_runs(status, started_at DESC);

CREATE TABLE audit_events (
    id TEXT PRIMARY KEY,
    certificate_id TEXT,
    event_type TEXT NOT NULL,
    actor TEXT NOT NULL,
    client_ip TEXT NOT NULL DEFAULT '',
    result TEXT NOT NULL,
    detail_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    FOREIGN KEY (certificate_id) REFERENCES certificates(id) ON DELETE SET NULL
);

CREATE INDEX audit_events_certificate_idx ON audit_events(certificate_id, created_at DESC);
CREATE INDEX audit_events_type_idx ON audit_events(event_type, created_at DESC);

CREATE TABLE system_settings (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    default_ca TEXT NOT NULL,
    default_acme_email TEXT NOT NULL DEFAULT '',
    default_key_type TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

INSERT INTO system_settings (id, default_ca, default_acme_email, default_key_type, updated_at)
VALUES (1, 'letsencrypt', '', 'ec-256', strftime('%Y-%m-%dT%H:%M:%fZ', 'now'));

-- +goose Down
DROP TABLE system_settings;
DROP TABLE audit_events;
DROP TABLE job_runs;
DROP TABLE renewal_policies;
DROP TABLE certificates;
DROP TABLE dns_credentials;
