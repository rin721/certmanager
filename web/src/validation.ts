// 表单边界校验只处理格式与安全约束，不执行任何网络请求。
export function isSafeCADirectoryURL(value: string): boolean {
  try {
    const parsed = new URL(value)
    return parsed.protocol === 'https:' && Boolean(parsed.host) && !parsed.username && !parsed.password && !parsed.hash
  } catch {
    return false
  }
}

export type RedundantACMEDomain = {
  domain: string
  wildcard: string
  primary: boolean
}

// parseSANDomains 统一解析表单中以换行或逗号分隔的 SAN。
export function parseSANDomains(value: string): string[] {
  return value.split(/[\n,]/).map((domain) => domain.trim()).filter(Boolean)
}

// findRedundantACMEDomain 查找只覆盖一级子域名的通配符冲突。
export function findRedundantACMEDomain(primary: string, sans: string[]): RedundantACMEDomain | undefined {
  const normalizedPrimary = primary.trim().toLowerCase()
  const domains = [normalizedPrimary, ...sans.map((domain) => domain.trim().toLowerCase()).filter(Boolean)]
  const wildcards = [...new Set(domains.filter((domain) => domain.startsWith('*.')))].sort()
  for (const domain of domains) {
    if (!domain || domain.startsWith('*.')) continue
    for (const wildcard of wildcards) {
      if (wildcardCoversDomain(wildcard, domain)) {
        return { domain, wildcard, primary: domain === normalizedPrimary }
      }
    }
  }
  return undefined
}

function wildcardCoversDomain(wildcard: string, domain: string): boolean {
  const suffix = `.${wildcard.slice(2)}`
  if (!domain.endsWith(suffix)) return false
  const leftmostLabel = domain.slice(0, -suffix.length)
  return Boolean(leftmostLabel) && !leftmostLabel.includes('.')
}
