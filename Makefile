GO ?= go
NPM ?= npm

.PHONY: dev frontend-dev backend-dev build test test-e2e deploy-test lint verify vuln license docker-build docker-up docker-down clean

dev:
	@echo "请在两个终端分别运行 make backend-dev 和 make frontend-dev"

frontend-dev:
	cd web && $(NPM) run dev

backend-dev:
	APP_ENV=development DATA_DIR=$${DATA_DIR:-$(CURDIR)/data} CERT_OUTPUT_DIR=$${CERT_OUTPUT_DIR:-$(CURDIR)/certs} ACME_HOME=$${ACME_HOME:-$(CURDIR)/data/acme} ACME_CHALLENGE_DIR=$${ACME_CHALLENGE_DIR:-$(CURDIR)/data/challenges} $(GO) run ./cmd/server

build:
	cd web && $(NPM) run build
	$(GO) build -trimpath -o bin/certmate ./cmd/server

test:
	$(GO) test ./...
	cd web && $(NPM) run test

test-e2e:
	cd web && $(NPM) run build && $(NPM) run test:e2e

deploy-test:
	bash -n scripts/deploy.sh
	bash -n scripts/deploy_test.sh
	bash scripts/deploy_test.sh

lint:
	$(GO) vet ./...
	cd web && $(NPM) run lint

verify:
	$(GO) test ./...
	$(GO) vet ./...
	$(MAKE) deploy-test
	cd web && $(NPM) run lint
	cd web && $(NPM) run test
	cd web && $(NPM) run build
	cd web && $(NPM) audit --audit-level=high --registry=https://registry.npmjs.org

vuln:
	$(GO) run golang.org/x/vuln/cmd/govulncheck@latest ./...
	cd web && $(NPM) audit --audit-level=high --registry=https://registry.npmjs.org

license:
	$(GO) run github.com/google/go-licenses@v1.6.0 report ./...
	cd web && npx --yes license-checker-rseidelsohn@5.0.1 --production --excludePackages 'certmate-web@0.1.0' --onlyAllow 'MIT;BSD-3-Clause;ISC'

docker-build:
	docker compose build

docker-up:
	docker compose up -d

docker-down:
	docker compose down

clean:
	rm -rf bin internal/webui/dist/assets web/playwright-report web/test-results .e2e-data .e2e-certs
