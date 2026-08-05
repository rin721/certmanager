// @vitest-environment jsdom

import '@testing-library/jest-dom/vitest'
import { cleanup, render, screen } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { afterEach, expect, test, vi } from 'vitest'
import App from './App'

afterEach(() => { cleanup(); vi.restoreAllMocks(); vi.unstubAllGlobals() })

test('显示后端返回的应用名称', async () => {
	  vi.stubGlobal('fetch', vi.fn(async (input: string | URL | Request) => {
	    const url = String(input)
	    if (url.endsWith('/api/v1/meta')) {
	      return new Response(JSON.stringify({ app_name: 'CertMate Test', environment: 'test', enable_acme: true, enable_self_signed: true }), { status: 200 })
	    }
	    if (url.endsWith('/api/v1/dashboard')) {
	      return new Response(JSON.stringify({ counts: { total: 0, active: 0, expiring: 0, expired: 0, failed: 0 }, recent_jobs: [], expiring_certificates: [] }), { status: 200 })
	    }
	    return new Response(JSON.stringify({ username: 'admin', authenticated: true, reauthenticated: false }), { status: 200 })
	  }))
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  render(<QueryClientProvider client={client}><App /></QueryClientProvider>)
	  expect(await screen.findByText('CertMate Test')).toBeInTheDocument()
	  expect(await screen.findByText(/欢迎，admin/)).toBeInTheDocument()
})
