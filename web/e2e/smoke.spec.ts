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
