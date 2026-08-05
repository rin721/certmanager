// @vitest-environment jsdom

import '@testing-library/jest-dom/vitest'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { afterEach, expect, test, vi } from 'vitest'
import { CertificateDetailPage, CertificateListPage, CreateCertificatePage } from './CertificatePages'
import { LoginPage } from './LoginPage'
import { RenewalSettingsPage } from './RenewalSettingsPage'
import { findRedundantACMEDomain, isSafeCADirectoryURL } from './validation'

afterEach(() => { cleanup(); vi.restoreAllMocks(); vi.unstubAllGlobals() })

function renderWithClient(element: React.ReactNode, route = '/') {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })
  return render(<QueryClientProvider client={client}><MemoryRouter initialEntries={[route]}>{element}</MemoryRouter></QueryClientProvider>)
}

test('登录页隐藏后端细节并显示稳定错误', async () => {
  vi.stubGlobal('fetch', vi.fn(async (input: string | URL | Request) => {
    if (String(input).endsWith('/api/v1/auth/csrf')) return new Response(JSON.stringify({ csrf_token: 'test-token' }), { status: 200 })
    return new Response(JSON.stringify({ error: { code: 'AUTH_INVALID_CREDENTIALS', message: '用户名或密码错误' } }), { status: 401 })
  }))
  renderWithClient(<LoginPage appName="CertMate" />)
  fireEvent.change(screen.getByLabelText('密码'), { target: { value: 'wrong-password' } })
  fireEvent.click(screen.getByRole('button', { name: '登录' }))
  expect(await screen.findByText('用户名或密码错误')).toBeInTheDocument()
  expect(screen.queryByText(/stack|SQL|bcrypt/i)).not.toBeInTheDocument()
})

test('证书列表显示模式、状态和有效期', async () => {
  vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({ items: [certificateFixture] }), { status: 200 })))
  renderWithClient(<CertificateListPage />)
  expect(await screen.findByText('example.com')).toBeInTheDocument()
  expect(screen.getByText('active')).toBeInTheDocument()
})

test('创建证书表单按五个步骤推进并校验域名字段', async () => {
  vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({ items: [] }), { status: 200 })))
  renderWithClient(<CreateCertificatePage />)
	expect(screen.getByText('证书类型')).toBeInTheDocument()
	fireEvent.click(screen.getByRole('button', { name: '下一步' }))
  fireEvent.change(await screen.findByLabelText('证书名称'), { target: { value: '测试证书' } })
  fireEvent.change(screen.getByLabelText('主域名'), { target: { value: 'example.com' } })
	fireEvent.change(screen.getByLabelText('SAN 域名'), { target: { value: '*.example.com\nwww.example.com' } })
  fireEvent.click(screen.getByRole('button', { name: '下一步' }))
  expect(await screen.findByLabelText('密钥类型')).toBeInTheDocument()
	fireEvent.click(screen.getByRole('button', { name: '下一步' }))
	expect(await screen.findByLabelText('安全输出目录名')).toBeInTheDocument()
	fireEvent.click(screen.getByRole('button', { name: '下一步' }))
	expect(await screen.findByText((_, element) => element?.tagName === 'P' && element.textContent === 'SAN：*.example.com, www.example.com')).toBeInTheDocument()
})

test('自动续签配置保存后显示立即生效', async () => {
  const policy = { enabled: true, cron_expression: '0 3 * * *', timezone: 'Asia/Shanghai', max_concurrency: 2, retry_count: 2, retry_interval_seconds: 60, updated_at: '2026-08-05T00:00:00Z' }
  vi.stubGlobal('fetch', vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
    const url = String(input)
    if (url.endsWith('/api/v1/auth/csrf')) return new Response(JSON.stringify({ csrf_token: 'test-token' }), { status: 200 })
    if (init?.method === 'PUT') return new Response(JSON.stringify({ policy: { ...policy, updated_at: '2026-08-05T00:01:00Z' }, status: { running: true, active_runs: 0 } }), { status: 200 })
    return new Response(JSON.stringify({ policy, status: { running: true, active_runs: 0, next_run_at: '2026-08-06T03:00:00Z' } }), { status: 200 })
  }))
  renderWithClient(<RenewalSettingsPage />)
  fireEvent.click(await screen.findByRole('button', { name: '保存并立即生效' }))
  expect(await screen.findByText('新策略已生效。')).toBeInTheDocument()
})

test('自定义 ACME Directory URL 只接受安全 HTTPS 地址', () => {
  expect(isSafeCADirectoryURL('https://acme.example.com/directory')).toBe(true)
  expect(isSafeCADirectoryURL('http://acme.example.com/directory')).toBe(false)
  expect(isSafeCADirectoryURL('https://user:password@acme.example.com/directory')).toBe(false)
  expect(isSafeCADirectoryURL('https://acme.example.com/directory#fragment')).toBe(false)
})

test('ACME 通配符冗余 SAN 在域名步骤被拒绝', async () => {
  const requests: string[] = []
  vi.stubGlobal('fetch', vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
	requests.push(`${init?.method ?? 'GET'} ${String(input)}`)
	return new Response(JSON.stringify({ items: [] }), { status: 200 })
  }))
  renderWithClient(<CreateCertificatePage />)
  fireEvent.click(screen.getByRole('button', { name: '公共 CA 证书' }))
  fireEvent.click(screen.getByRole('button', { name: '下一步' }))
  fireEvent.change(await screen.findByLabelText('证书名称'), { target: { value: '公共证书' } })
  fireEvent.change(screen.getByLabelText('主域名'), { target: { value: 'example.com' } })
  fireEvent.change(screen.getByLabelText('SAN 域名'), { target: { value: '*.example.com\nwww.example.com' } })
  fireEvent.click(screen.getByRole('button', { name: '下一步' }))
  expect(await screen.findByText('SAN 域名 "www.example.com" 已被通配符 "*.example.com" 覆盖，请删除其中一个')).toBeInTheDocument()
  expect(requests.some((request) => request.startsWith('POST '))).toBe(false)

	fireEvent.change(screen.getByLabelText('主域名'), { target: { value: 'www.example.com' } })
  fireEvent.change(screen.getByLabelText('SAN 域名'), { target: { value: '*.example.com' } })
	fireEvent.click(screen.getByRole('button', { name: '下一步' }))
	expect(await screen.findByText('主域名 "www.example.com" 已被通配符 "*.example.com" 覆盖，请将主域名改为基础域名或删除通配符')).toBeInTheDocument()
	expect(screen.getByLabelText('主域名')).toHaveAttribute('aria-invalid', 'true')

	fireEvent.change(screen.getByLabelText('主域名'), { target: { value: 'example.com' } })
  fireEvent.click(screen.getByRole('button', { name: '下一步' }))
  expect(await screen.findByLabelText('密钥类型')).toBeInTheDocument()
})

test('ACME 通配符覆盖规则只匹配一级子域名', () => {
  expect(findRedundantACMEDomain('example.com', ['*.example.com', 'www.example.com'])).toEqual({
	domain: 'www.example.com', wildcard: '*.example.com', primary: false,
  })
  expect(findRedundantACMEDomain('example.com', ['*.example.com', 'a.b.example.com'])).toBeUndefined()
	expect(findRedundantACMEDomain('www.example.com', ['*.example.com'])).toEqual({
	domain: 'www.example.com', wildcard: '*.example.com', primary: true,
	})
})

test('证书详情页提供兼容的重新签发操作', async () => {
  const requests: string[] = []
  vi.stubGlobal('fetch', vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
    const url = String(input)
    requests.push(`${init?.method ?? 'GET'} ${url}`)
    if (url.endsWith('/api/v1/auth/csrf')) return new Response(JSON.stringify({ csrf_token: 'test-token' }), { status: 200 })
    if (init?.method === 'POST' && url.endsWith('/issue')) return new Response(JSON.stringify(certificateFixture), { status: 200 })
    return new Response(JSON.stringify(certificateFixture), { status: 200 })
  }))
  renderWithClient(<Routes><Route path="/certificates/:id" element={<CertificateDetailPage />} /></Routes>, '/certificates/cert-1')
  fireEvent.click(await screen.findByRole('button', { name: '重新签发' }))
  await waitFor(() => expect(requests.some((item) => item.endsWith('POST /api/v1/certificates/cert-1/issue'))).toBe(true))
})

test('旧失败证书重试时显示通配符冗余错误', async () => {
  const message = 'SAN 域名 "www.example.com" 已被通配符 "*.example.com" 覆盖，请删除其中一个'
  vi.stubGlobal('fetch', vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
	const url = String(input)
	if (url.endsWith('/api/v1/auth/csrf')) return new Response(JSON.stringify({ csrf_token: 'test-token' }), { status: 200 })
	if (init?.method === 'POST' && url.endsWith('/issue')) return new Response(JSON.stringify({ error: { code: 'CERT_DOMAIN_REDUNDANT', message } }), { status: 400 })
	return new Response(JSON.stringify({ ...certificateFixture, status: 'failed', domains: ['example.com', '*.example.com', 'www.example.com'] }), { status: 200 })
  }))
  renderWithClient(<Routes><Route path="/certificates/:id" element={<CertificateDetailPage />} /></Routes>, '/certificates/cert-1')
  fireEvent.click(await screen.findByRole('button', { name: '重试签发' }))
  expect(await screen.findByText(message)).toBeInTheDocument()
})

test('失败证书只提供重试和删除且无文件时仅删除管理记录', async () => {
	const requests: Array<{ method: string; url: string; body?: string }> = []
	const consoleError = vi.spyOn(console, 'error').mockImplementation(() => undefined)
	vi.stubGlobal('fetch', vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
		const url = String(input)
		requests.push({ method: init?.method ?? 'GET', url, body: init?.body as string | undefined })
		if (url.endsWith('/api/v1/auth/csrf')) return new Response(JSON.stringify({ csrf_token: 'test-token' }), { status: 200 })
		if (url.endsWith('/files')) return new Response(JSON.stringify({ items: [] }), { status: 200 })
		if (init?.method === 'DELETE') return new Response(null, { status: 204 })
		return new Response(JSON.stringify({ ...certificateFixture, name: '失败记录', mode: 'acme', status: 'failed' }), { status: 200 })
	}))
	renderWithClient(<Routes><Route path="/certificates/:id" element={<CertificateDetailPage />} /><Route path="/certificates" element={<div>证书列表</div>} /></Routes>, '/certificates/cert-1')

	expect(await screen.findByRole('button', { name: '重试签发' })).toBeInTheDocument()
	expect(screen.getByRole('button', { name: '删除失败记录' })).toBeInTheDocument()
	expect(screen.queryByRole('button', { name: '手动续签' })).not.toBeInTheDocument()
	expect(screen.queryByRole('button', { name: '强制续签' })).not.toBeInTheDocument()
	expect(screen.queryByRole('button', { name: '撤销' })).not.toBeInTheDocument()
	expect(screen.getByText(/failed 表示这条管理记录未能完成签发/)).toBeInTheDocument()

	fireEvent.click(screen.getByRole('tab', { name: '证书文件' }))
	expect(await screen.findByText('当前记录没有已发布的证书文件。首次签发失败时这是正常状态。')).toBeInTheDocument()
	expect(screen.queryByRole('link', { name: '下载' })).not.toBeInTheDocument()

	fireEvent.click(screen.getByRole('button', { name: '删除失败记录' }))
	const deleteFilesCheckbox = await screen.findByRole('checkbox', { name: '没有已发布的证书文件，只删除管理记录' })
	expect(deleteFilesCheckbox).toBeDisabled()
	fireEvent.change(screen.getByLabelText('输入证书名称 失败记录 以确认'), { target: { value: '失败记录' } })
	fireEvent.change(screen.getByLabelText('管理员密码'), { target: { value: 'correct-password' } })
	fireEvent.click(screen.getByRole('button', { name: '确认删除' }))
	expect(await screen.findByText('证书列表')).toBeInTheDocument()
	const deleteRequest = requests.find((request) => request.method === 'DELETE')
	expect(deleteRequest).toBeDefined()
	expect(JSON.parse(deleteRequest?.body ?? '{}')).toMatchObject({ delete_files: false, confirm_name: '失败记录' })
	await waitFor(() => expect(consoleError.mock.calls.flat().join(' ')).not.toContain('Blocked aria-hidden'))
})

test('删除文件备份失败时显示后端安全提示', async () => {
	const message = '证书文件备份失败，管理记录未删除'
	vi.stubGlobal('fetch', vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
		const url = String(input)
		if (url.endsWith('/api/v1/auth/csrf')) return new Response(JSON.stringify({ csrf_token: 'test-token' }), { status: 200 })
		if (url.endsWith('/files')) return new Response(JSON.stringify({ items: [{ type: 'cert', filename: 'cert.pem', private: false, container_path: '/certs/example-com/cert.pem' }] }), { status: 200 })
		if (init?.method === 'DELETE') return new Response(JSON.stringify({ error: { code: 'CERT_DELETE_FILES_BACKUP_FAILED', message } }), { status: 409 })
		return new Response(JSON.stringify({ ...certificateFixture, name: '不完整证书', mode: 'acme', status: 'failed' }), { status: 200 })
	}))
	renderWithClient(<Routes><Route path="/certificates/:id" element={<CertificateDetailPage />} /></Routes>, '/certificates/cert-1')
	fireEvent.click(await screen.findByRole('button', { name: '删除失败记录' }))
	const deleteFilesCheckbox = await screen.findByRole('checkbox', { name: '同时删除证书文件（先创建备份）' })
	fireEvent.click(deleteFilesCheckbox)
	fireEvent.change(screen.getByLabelText('输入证书名称 不完整证书 以确认'), { target: { value: '不完整证书' } })
	fireEvent.change(screen.getByLabelText('管理员密码'), { target: { value: 'correct-password' } })
	fireEvent.click(screen.getByRole('button', { name: '确认删除' }))
	expect(await screen.findByText(message)).toBeInTheDocument()
})

test('私钥查看要求二次认证且响应只保存在组件内存', async () => {
  vi.stubGlobal('fetch', vi.fn(async (input: string | URL | Request) => {
    const url = String(input)
    if (url.endsWith('/files')) return new Response(JSON.stringify({ items: [{ type: 'private-key', filename: 'privkey.pem', private: true, container_path: '/certs/example-com/privkey.pem' }] }), { status: 200 })
    if (url.endsWith('/api/v1/auth/csrf')) return new Response(JSON.stringify({ csrf_token: 'test-token' }), { status: 200 })
    if (url.endsWith('/reveal')) return new Response('PRIVATE TEST VALUE', { status: 200 })
    return new Response(JSON.stringify(certificateFixture), { status: 200 })
  }))
  renderWithClient(<Routes><Route path="/certificates/:id" element={<CertificateDetailPage />} /></Routes>, '/certificates/cert-1')
  fireEvent.click(await screen.findByRole('tab', { name: '证书文件' }))
  fireEvent.click(await screen.findByRole('button', { name: '查看' }))
  expect(screen.getByText('重新认证以查看私钥')).toBeInTheDocument()
  fireEvent.change(screen.getByLabelText('管理员密码'), { target: { value: 'test-password' } })
  fireEvent.click(screen.getByRole('button', { name: '确认查看' }))
  expect(await screen.findByText('PRIVATE TEST VALUE')).toBeInTheDocument()
  fireEvent.click(screen.getByRole('button', { name: '关闭' }))
  await waitFor(() => expect(screen.queryByText('PRIVATE TEST VALUE')).not.toBeInTheDocument())
})

const certificateFixture = {
  id: 'cert-1', name: 'Example', mode: 'self_signed', primary_domain: 'example.com', domains: ['example.com'],
  key_type: 'ec-256', status: 'active', output_directory: 'example-com', issuer: 'Example', serial_number: '1',
  not_before: '2026-08-05T00:00:00Z', not_after: '2027-08-05T00:00:00Z', fingerprint_sha256: 'AA',
  auto_renew_enabled: true, renew_before_days: 30, self_signed_valid_days: 365, create_renewed_marker: true,
  created_at: '2026-08-05T00:00:00Z', updated_at: '2026-08-05T00:00:00Z',
}
