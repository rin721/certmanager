import { expect, test } from '@playwright/test'

test('管理员完成自签名证书与动态续签 smoke 流程', async ({ page }) => {
  const suffix = Date.now().toString(36)
  const certificateName = `E2E ${suffix}`
  const domain = `${suffix}.example.test`

  await page.goto('/login')
  await page.getByLabel('用户名').fill('admin')
  await page.getByLabel('密码').fill('e2e-test-password')
  await page.getByRole('button', { name: '登录' }).click()
  await expect(page.getByText(/欢迎，admin/)).toBeVisible()

  await page.getByRole('link', { name: '创建证书' }).click()
	const next = () => page.locator('button[type="button"]').filter({ hasText: /^下一步$/ })
	await next().click()
  await page.getByLabel('证书名称').fill(certificateName)
  await page.getByLabel('主域名').fill(domain)
	await next().click()
	await expect(page.getByLabel('密钥类型')).toBeVisible()
	await next().click()
  await page.getByLabel('安全输出目录名').fill(`e2e-${suffix}`)
	await next().click()
	const createButton = page.getByRole('button', { name: '确认并创建' })
	await expect(createButton).toBeEnabled()
	// 提交后按钮会立即切换为“正在签发”，强制一次真实点击可避免定位器因文本变化重试。
	await createButton.click({ force: true })
  await expect(page.getByRole('heading', { name: certificateName })).toBeVisible()

  await page.getByRole('tab', { name: '证书文件' }).click()
	const fullchainRow = page.getByRole('row').filter({ hasText: 'fullchain.pem' })
  const downloadPromise = page.waitForEvent('download')
  await fullchainRow.getByRole('link', { name: '下载' }).click()
  const download = await downloadPromise
  expect(download.suggestedFilename()).toBe('fullchain.pem')

  await page.getByRole('link', { name: '自动续签' }).click()
  await page.getByRole('button', { name: '保存并立即生效' }).click()
  await expect(page.getByText('新策略已生效。')).toBeVisible()

  await page.getByRole('button', { name: '退出' }).click()
  await expect(page.getByRole('heading', { name: /登录 CertMate/ })).toBeVisible()
})

test('ACME 表单在提交前拒绝通配符冗余 SAN', async ({ page }) => {
  await page.goto('/login')
  await page.getByLabel('用户名').fill('admin')
  await page.getByLabel('密码').fill('e2e-test-password')
  await page.getByRole('button', { name: '登录' }).click()
  await expect(page.getByText(/欢迎，admin/)).toBeVisible()

  await page.getByRole('link', { name: '创建证书' }).click()
	await page.getByRole('button', { name: '公共 CA 证书' }).click()
	const next = () => page.locator('button[type="button"]').filter({ hasText: /^下一步$/ })
	await next().click()
	await page.getByLabel('证书名称').fill('冗余域名校验')
	await page.getByLabel('主域名').fill('example.com')
	await page.getByLabel('SAN 域名').fill('*.example.com\nwww.example.com')
	await next().click()
	await expect(page.getByText('SAN 域名 "www.example.com" 已被通配符 "*.example.com" 覆盖，请删除其中一个')).toBeVisible()
	await expect(page.getByLabel('SAN 域名')).toBeVisible()
})

test('失败记录没有证书文件时可直接删除管理记录', async ({ page }) => {
	const accessibilityErrors: string[] = []
	let deletePayload: Record<string, unknown> | undefined
	page.on('console', (message) => {
		if (message.text().includes('aria-hidden')) accessibilityErrors.push(message.text())
	})

	await page.goto('/login')
	await page.getByLabel('用户名').fill('admin')
	await page.getByLabel('密码').fill('e2e-test-password')
	await page.getByRole('button', { name: '登录' }).click()
	await expect(page.getByText(/欢迎，admin/)).toBeVisible()

	const failedCertificate = {
		id: 'failed-e2e', name: 'E2E 失败记录', mode: 'acme', primary_domain: 'example.com', domains: ['example.com'],
		key_type: 'ec-256', status: 'failed', output_directory: 'failed-e2e', issuer: '', serial_number: '',
		fingerprint_sha256: '', auto_renew_enabled: true, renew_before_days: 30, create_renewed_marker: true,
		created_at: '2026-08-05T00:00:00Z', updated_at: '2026-08-05T00:00:00Z', last_error: '签发失败',
	}
	const zoneError = 'Cloudflare 无法访问域名 "example.com" 的 Zone；请确认 Token 有效，具备 Zone:Zone:Read 和 Zone:DNS:Edit 权限，资源范围包含该 Zone，且 Token IP 限制允许当前服务器'
	await page.route('**/api/v1/certificates/failed-e2e/issue', (route) => route.fulfill({
		status: 400, contentType: 'application/json',
		body: JSON.stringify({ error: { code: 'CERT_DNS_ZONE_UNAVAILABLE', message: zoneError } }),
	}))
	await page.route('**/api/v1/certificates/failed-e2e', async (route) => {
		if (route.request().method() === 'DELETE') {
			deletePayload = route.request().postDataJSON() as Record<string, unknown>
			await route.fulfill({ status: 204 })
			return
		}
		await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(failedCertificate) })
	})
	await page.route('**/api/v1/certificates/failed-e2e/files', (route) => route.fulfill({
		status: 200, contentType: 'application/json', body: JSON.stringify({ items: [] }),
	}))

	await page.goto('/certificates/failed-e2e')
	await expect(page.getByRole('button', { name: '重试签发' })).toBeVisible()
	await expect(page.getByRole('button', { name: '撤销' })).toHaveCount(0)
	await page.getByRole('button', { name: '重试签发' }).click()
	await expect(page.getByText(zoneError)).toBeVisible()
	await page.getByRole('button', { name: '删除失败记录' }).click()
	await expect(page.getByRole('checkbox', { name: '没有已发布的证书文件，只删除管理记录' })).toBeDisabled()
	await page.getByLabel('输入证书名称 E2E 失败记录 以确认').fill('E2E 失败记录')
	await page.getByLabel('管理员密码').fill('e2e-test-password')
	await page.getByRole('button', { name: '确认删除' }).click()
	await expect(page).toHaveURL(/\/certificates$/)
	expect(deletePayload).toMatchObject({ confirm_name: 'E2E 失败记录', delete_files: false })
	expect(accessibilityErrors).toEqual([])
})
