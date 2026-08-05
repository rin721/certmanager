// 表单边界校验只处理格式与安全约束，不执行任何网络请求。
export function isSafeCADirectoryURL(value: string): boolean {
  try {
    const parsed = new URL(value)
    return parsed.protocol === 'https:' && Boolean(parsed.host) && !parsed.username && !parsed.password && !parsed.hash
  } catch {
    return false
  }
}
