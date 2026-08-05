-- +goose Up
ALTER TABLE dns_credentials ADD COLUMN acme_dns_code TEXT NOT NULL DEFAULT '';
ALTER TABLE dns_credentials ADD COLUMN masked_fields_json TEXT NOT NULL DEFAULT '[]';

-- +goose Down
ALTER TABLE dns_credentials DROP COLUMN masked_fields_json;
ALTER TABLE dns_credentials DROP COLUMN acme_dns_code;
