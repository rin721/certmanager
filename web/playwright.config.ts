import { defineConfig, devices } from '@playwright/test'
import path from 'node:path'

const repositoryRoot = path.resolve(import.meta.dirname, '..')

export default defineConfig({
  testDir: './e2e',
  timeout: 60_000,
  expect: { timeout: 10_000 },
  fullyParallel: false,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? 'github' : 'list',
  use: {
    baseURL: 'http://127.0.0.1:18089',
    trace: 'retain-on-failure',
    ...devices['Desktop Chrome'],
  },
  webServer: {
	command: 'go -C .. run ./cmd/server',
    cwd: import.meta.dirname,
    url: 'http://127.0.0.1:18089/readyz',
    reuseExistingServer: !process.env.CI,
    timeout: 120_000,
    env: {
      ...process.env,
      APP_ENV: 'test',
      LISTEN_ADDR: '127.0.0.1:18089',
      ADMIN_USERNAME: 'admin',
      ADMIN_PASSWORD: 'e2e-test-password',
      SESSION_SECRET: '0123456789abcdef0123456789abcdef',
      SESSION_COOKIE_SECURE: 'false',
      ENABLE_ACME: 'false',
      ENABLE_SELF_SIGNED: 'true',
      DATA_DIR: path.join(repositoryRoot, '.e2e-data'),
      CERT_OUTPUT_DIR: path.join(repositoryRoot, '.e2e-certs'),
      ACME_HOME: path.join(repositoryRoot, '.e2e-data', 'acme'),
      ACME_CHALLENGE_DIR: path.join(repositoryRoot, '.e2e-data', 'challenges'),
      LOG_LEVEL: 'warn',
	  OPENSSL_BINARY: process.env.OPENSSL_BINARY ?? 'openssl',
    },
  },
})
