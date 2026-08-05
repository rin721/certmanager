export type AppMeta = {
  app_name: string
  environment: string
  enable_acme: boolean
  enable_self_signed: boolean
}

export type CurrentUser = {
  username: string
  authenticated: true
  reauthenticated: boolean
}

export type Certificate = {
  id: string
  name: string
  mode: 'acme' | 'self_signed'
  primary_domain: string
  domains: string[]
  key_type: string
  status: string
  output_directory: string
  issuer: string
  serial_number: string
  not_before?: string
  not_after?: string
  fingerprint_sha256: string
  auto_renew_enabled: boolean
  renew_before_days: number
  self_signed_valid_days?: number
  create_renewed_marker: boolean
  created_at: string
  updated_at: string
  last_renewed_at?: string
  last_error?: string
}

export type CertificateFile = {
  type: 'cert' | 'chain' | 'fullchain' | 'private-key'
  filename: string
  private: boolean
  container_path: string
}

export type CreateSelfSignedCertificate = {
  mode: 'self_signed'
  name: string
  primary_domain: string
  sans: string[]
  key_type: 'ec-256' | 'rsa-2048' | 'rsa-3072'
  valid_days: number
  output_directory: string
  auto_renew_enabled: boolean
  renew_before_days: number
  create_renewed_marker: boolean
}

export type CreateACMECertificate = {
  mode: 'acme'
  name: string
  primary_domain: string
  sans: string[]
  key_type: 'ec-256' | 'rsa-2048' | 'rsa-3072'
  output_directory: string
  auto_renew_enabled: boolean
  renew_before_days: number
  create_renewed_marker: boolean
  challenge_type: 'dns-01' | 'http-01'
  dns_credential_id: string
  ca_directory_url: string
  acme_email: string
}

export type DNSProviderField = {
  name: string
  label: string
  required: boolean
  secret: boolean
  placeholder?: string
  description?: string
}

export type DNSProvider = {
  provider_code: string
  display_name: string
  acme_dns_code: string
  fields: DNSProviderField[]
  documentation_hint: string
  custom: boolean
}

export type DNSCredential = {
  id: string
  name: string
  provider: string
  acme_dns_code: string
  source_mode: 'encrypted' | 'environment'
  masked_fields: string[]
  environment_refs?: Record<string, string>
  created_at: string
  updated_at: string
}

export type DNSCredentialInput = {
  name: string
  provider: string
  custom_acme_code?: string
  source_mode: 'encrypted' | 'environment'
  values?: Record<string, string>
  environment_refs?: Record<string, string>
}

export type DNSCredentialReference = Pick<Certificate, 'id' | 'name' | 'primary_domain' | 'status'>

export type RenewalPolicy = {
  enabled: boolean
  cron_expression: string
  timezone: string
  max_concurrency: number
  retry_count: number
  retry_interval_seconds: number
  updated_at?: string
}

export type SchedulerStatus = {
  running: boolean
  last_run_at?: string
  next_run_at?: string
  last_error?: string
  active_runs: number
}

export type JobRun = {
  id: string
  certificate_id?: string
  job_type: string
  status: string
  started_at: string
  finished_at?: string
  exit_code?: number
  sanitized_output?: string
  error_message?: string
  attempt: number
}

export type AuditEvent = {
  id: string
  certificate_id?: string
  event_type: string
  actor: string
  client_ip?: string
  result: string
  detail?: Record<string, unknown>
  created_at: string
}

export type Dashboard = {
  counts: { total: number; active: number; expiring: number; expired: number; failed: number }
  recent_jobs: JobRun[]
  expiring_certificates: Certificate[]
}

export type SystemInfo = {
  application_version: string
  go_version: string
  acme_sh_version: string
  openssl_version: string
  sqlite_status: string
  data_directory: string
  certificate_directory: string
  timezone: string
  scheduler: SchedulerStatus
}

type ApiErrorBody = { error?: { code?: string; message?: string } }

export class ApiError extends Error {
  constructor(
    public readonly status: number,
    public readonly code: string,
    message: string,
  ) {
    super(message)
  }
}

let csrfToken: string | undefined

async function request<T>(url: string, init?: RequestInit): Promise<T> {
  const response = await fetch(url, { credentials: 'same-origin', ...init })
  if (!response.ok) {
    let body: ApiErrorBody = {}
    try {
      body = (await response.json()) as ApiErrorBody
    } catch {
      // 非 JSON 错误使用稳定的通用消息，不向界面暴露内部响应。
    }
    throw new ApiError(response.status, body.error?.code ?? 'REQUEST_FAILED', body.error?.message ?? '请求失败')
  }
  return response.json() as Promise<T>
}

async function getCSRFToken(): Promise<string> {
  if (csrfToken) return csrfToken
  const result = await request<{ csrf_token: string }>('/api/v1/auth/csrf')
  csrfToken = result.csrf_token
  return csrfToken
}

async function write<T>(url: string, body?: unknown): Promise<T> {
  const token = await getCSRFToken()
  return request<T>(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': token },
    body: JSON.stringify(body ?? {}),
  })
}

async function writeMethod<T>(method: 'POST' | 'PUT' | 'PATCH' | 'DELETE', url: string, body?: unknown): Promise<T> {
  const token = await getCSRFToken()
  const response = await fetch(url, {
    method,
    credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': token },
    body: body === undefined ? undefined : JSON.stringify(body),
  })
  if (!response.ok) {
    let errorBody: ApiErrorBody = {}
    try { errorBody = (await response.json()) as ApiErrorBody } catch { /* 保持通用错误 */ }
    throw new ApiError(response.status, errorBody.error?.code ?? 'REQUEST_FAILED', errorBody.error?.message ?? '请求失败')
  }
  if (response.status === 204) return undefined as T
  return response.json() as Promise<T>
}

async function requestText(url: string, init?: RequestInit): Promise<string> {
  const response = await fetch(url, { credentials: 'same-origin', ...init })
  if (!response.ok) {
    let message = '请求失败'
    try {
      const body = (await response.json()) as ApiErrorBody
      message = body.error?.message ?? message
    } catch {
      // 保持通用错误消息。
    }
    throw new ApiError(response.status, 'REQUEST_FAILED', message)
  }
  return response.text()
}

export async function getMeta(): Promise<AppMeta> {
	  return request<AppMeta>('/api/v1/meta')
}

export async function getCurrentUser(): Promise<CurrentUser | null> {
  try {
    return await request<CurrentUser>('/api/v1/auth/me')
  } catch (error) {
    if (error instanceof ApiError && error.status === 401) return null
    throw error
  }
}

export async function login(username: string, password: string): Promise<CurrentUser> {
  const result = await write<{ username: string; authenticated: true }>('/api/v1/auth/login', { username, password })
  return { ...result, reauthenticated: false }
}

export async function logout(): Promise<void> {
  await write('/api/v1/auth/logout')
}

export async function reauthenticate(password: string): Promise<void> {
  await write('/api/v1/auth/reauthenticate', { password })
}

export async function listCertificates(): Promise<Certificate[]> {
  const result = await request<{ items: Certificate[] }>('/api/v1/certificates')
  return result.items
}

export async function getDashboard(): Promise<Dashboard> {
  return request<Dashboard>('/api/v1/dashboard')
}

export async function listJobs(filters: { certificateId?: string; status?: string; jobType?: string; since?: string } = {}): Promise<JobRun[]> {
  const query = new URLSearchParams()
  if (filters.certificateId) query.set('certificate_id', filters.certificateId)
  if (filters.status) query.set('status', filters.status)
  if (filters.jobType) query.set('job_type', filters.jobType)
  if (filters.since) query.set('since', filters.since)
  const result = await request<{ items: JobRun[] }>(`/api/v1/jobs?${query.toString()}`)
  return result.items
}

export async function listAuditEvents(certificateId?: string): Promise<AuditEvent[]> {
  const query = new URLSearchParams()
  if (certificateId) query.set('certificate_id', certificateId)
  const result = await request<{ items: AuditEvent[] }>(`/api/v1/audit-events?${query.toString()}`)
  return result.items
}

export async function getSystemInfo(): Promise<SystemInfo> {
  return request<SystemInfo>('/api/v1/system/info')
}

export async function createSelfSignedCertificate(value: CreateSelfSignedCertificate): Promise<Certificate> {
  return write<Certificate>('/api/v1/certificates', value)
}

export async function createACMECertificate(value: CreateACMECertificate): Promise<Certificate> {
  return write<Certificate>('/api/v1/certificates', value)
}

export async function listDNSProviders(): Promise<DNSProvider[]> {
  const result = await request<{ items: DNSProvider[] }>('/api/v1/dns-providers')
  return result.items
}

export async function listDNSCredentials(): Promise<DNSCredential[]> {
  const result = await request<{ items: DNSCredential[] }>('/api/v1/dns-credentials')
  return result.items
}

export async function createDNSCredential(value: DNSCredentialInput): Promise<DNSCredential> {
  return write<DNSCredential>('/api/v1/dns-credentials', value)
}

export async function updateDNSCredential(id: string, value: DNSCredentialInput): Promise<DNSCredential> {
  return writeMethod<DNSCredential>('PATCH', `/api/v1/dns-credentials/${encodeURIComponent(id)}`, value)
}

export async function renameDNSCredential(id: string, name: string): Promise<DNSCredential> {
  return writeMethod<DNSCredential>('PATCH', `/api/v1/dns-credentials/${encodeURIComponent(id)}`, { name })
}

export async function testDNSCredential(id: string): Promise<void> {
  await write<void>(`/api/v1/dns-credentials/${encodeURIComponent(id)}/test`)
}

export async function listDNSCredentialReferences(id: string): Promise<DNSCredentialReference[]> {
  const result = await request<{ items: DNSCredentialReference[] }>(`/api/v1/dns-credentials/${encodeURIComponent(id)}/references`)
  return result.items
}

export async function deleteDNSCredential(id: string): Promise<void> {
  await writeMethod<void>('DELETE', `/api/v1/dns-credentials/${encodeURIComponent(id)}`)
}

export async function getRenewalPolicy(): Promise<{ policy: RenewalPolicy; status: SchedulerStatus }> {
  return request('/api/v1/renewal-policy')
}

export async function updateRenewalPolicy(policy: RenewalPolicy): Promise<{ policy: RenewalPolicy; status: SchedulerStatus }> {
  return writeMethod('PUT', '/api/v1/renewal-policy', policy)
}

export async function runRenewalNow(): Promise<void> {
  await write('/api/v1/renewal-policy/run-now')
}

export async function renewCertificate(id: string, force = false): Promise<Certificate> {
  return write<Certificate>(`/api/v1/certificates/${encodeURIComponent(id)}/${force ? 'force-renew' : 'renew'}`)
}

export async function revokeCertificate(id: string, password: string): Promise<Certificate> {
  return write<Certificate>(`/api/v1/certificates/${encodeURIComponent(id)}/revoke`, { password })
}

export async function deleteCertificate(id: string, password: string, confirmName: string, deleteFiles: boolean): Promise<void> {
  await writeMethod<void>('DELETE', `/api/v1/certificates/${encodeURIComponent(id)}`, { password, confirm_name: confirmName, delete_files: deleteFiles })
}

export async function getCertificate(id: string): Promise<Certificate> {
  return request<Certificate>(`/api/v1/certificates/${encodeURIComponent(id)}`)
}

export async function updateCertificate(id: string, value: Pick<Certificate, 'name' | 'auto_renew_enabled' | 'renew_before_days' | 'create_renewed_marker'>): Promise<Certificate> {
  return writeMethod<Certificate>('PATCH', `/api/v1/certificates/${encodeURIComponent(id)}`, value)
}

export async function listCertificateFiles(id: string): Promise<CertificateFile[]> {
  const result = await request<{ items: CertificateFile[] }>(`/api/v1/certificates/${encodeURIComponent(id)}/files`)
  return result.items
}

export async function getCertificateFile(id: string, type: CertificateFile['type']): Promise<string> {
  return requestText(`/api/v1/certificates/${encodeURIComponent(id)}/files/${encodeURIComponent(type)}`)
}

export async function revealPrivateKey(id: string, password: string): Promise<string> {
  const token = await getCSRFToken()
  return requestText(`/api/v1/certificates/${encodeURIComponent(id)}/files/private-key/reveal`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': token },
    body: JSON.stringify({ password }),
  })
}

export async function auditPrivateKeyCopy(id: string): Promise<void> {
  await writeMethod<void>('POST', `/api/v1/certificates/${encodeURIComponent(id)}/files/private-key/copy-audit`)
}

export async function downloadCertificateArchive(id: string, includePrivateKey: boolean, password = ''): Promise<void> {
  const token = await getCSRFToken()
  const response = await fetch(`/api/v1/certificates/${encodeURIComponent(id)}/files/archive`, {
    method: 'POST', credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': token },
    body: JSON.stringify({ include_private_key: includePrivateKey, password }),
  })
  if (!response.ok) {
    let errorBody: ApiErrorBody = {}
    try { errorBody = (await response.json()) as ApiErrorBody } catch { /* 保持通用错误 */ }
    throw new ApiError(response.status, errorBody.error?.code ?? 'REQUEST_FAILED', errorBody.error?.message ?? '压缩包下载失败')
  }
  const blob = await response.blob()
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = 'certificate-bundle.zip'
  link.click()
  setTimeout(() => URL.revokeObjectURL(url), 0)
}

export function certificateDownloadURL(id: string, type: CertificateFile['type']): string {
  return `/api/v1/certificates/${encodeURIComponent(id)}/files/${encodeURIComponent(type)}/download`
}
