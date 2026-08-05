import HealthAndSafetyOutlinedIcon from '@mui/icons-material/HealthAndSafetyOutlined'
import LogoutOutlinedIcon from '@mui/icons-material/LogoutOutlined'
import {
  Alert,
  AppBar,
  Box,
  Button,
  CircularProgress,
  Container,
  Toolbar,
  Typography,
} from '@mui/material'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { lazy, Suspense, useEffect } from 'react'
import { BrowserRouter, Link as RouterLink, Navigate, Route, Routes, useNavigate } from 'react-router-dom'
import { getCurrentUser, getMeta, logout } from './api'
import { LoginPage } from './LoginPage'

const DashboardPage = lazy(() => import('./CertificatePages').then((module) => ({ default: module.DashboardPage })))
const CertificateListPage = lazy(() => import('./CertificatePages').then((module) => ({ default: module.CertificateListPage })))
const CreateCertificatePage = lazy(() => import('./CertificatePages').then((module) => ({ default: module.CreateCertificatePage })))
const CertificateDetailPage = lazy(() => import('./CertificatePages').then((module) => ({ default: module.CertificateDetailPage })))
const DNSCredentialsPage = lazy(() => import('./DNSCredentialsPage').then((module) => ({ default: module.DNSCredentialsPage })))
const RenewalSettingsPage = lazy(() => import('./RenewalSettingsPage').then((module) => ({ default: module.RenewalSettingsPage })))
const JobsPage = lazy(() => import('./OperationsPages').then((module) => ({ default: module.JobsPage })))
const AuditPage = lazy(() => import('./OperationsPages').then((module) => ({ default: module.AuditPage })))
const SystemInfoPage = lazy(() => import('./OperationsPages').then((module) => ({ default: module.SystemInfoPage })))

export default function App() {
  const meta = useQuery({ queryKey: ['meta'], queryFn: getMeta, staleTime: 60_000 })

  useEffect(() => {
    if (meta.data?.app_name) document.title = meta.data.app_name
  }, [meta.data?.app_name])

  if (meta.isPending) return <FullPageProgress />
  if (meta.isError) return <Container sx={{ py: 8 }}><Alert severity="error">应用服务暂时不可用。</Alert></Container>

  return (
    <BrowserRouter>
		<Suspense fallback={<Box sx={{ py: 6, textAlign: 'center' }}><CircularProgress /></Box>}><Routes>
        <Route path="/login" element={<LoginRoute appName={meta.data.app_name} />} />
        <Route path="/*" element={<AuthenticatedArea appName={meta.data.app_name} environment={meta.data.environment} />} />
		</Routes></Suspense>
    </BrowserRouter>
  )
}

function LoginRoute({ appName }: { appName: string }) {
  const currentUser = useQuery({ queryKey: ['current-user'], queryFn: getCurrentUser, retry: false })
  if (currentUser.isPending) return <FullPageProgress />
  if (currentUser.data) return <Navigate to="/" replace />
  return <LoginPage appName={appName} />
}

function AuthenticatedArea({ appName, environment }: { appName: string; environment: string }) {
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const currentUser = useQuery({ queryKey: ['current-user'], queryFn: getCurrentUser, retry: false })
  const signOut = useMutation({
    mutationFn: logout,
    onSuccess: async () => {
      queryClient.setQueryData(['current-user'], null)
      await navigate('/login', { replace: true })
    },
  })
  if (currentUser.isPending) return <FullPageProgress />
  if (!currentUser.data) return <Navigate to="/login" replace />

  return (
    <>
      <AppBar position="static" color="inherit" elevation={1}>
        <Toolbar>
          <HealthAndSafetyOutlinedIcon color="primary" sx={{ mr: 1.5 }} />
          <Typography variant="h6" component="h1" sx={{ flexGrow: 1 }}>{appName}</Typography>
          <Button color="inherit" component={RouterLink} to="/">仪表盘</Button>
          <Button color="inherit" component={RouterLink} to="/certificates">证书</Button>
          <Button color="inherit" component={RouterLink} to="/dns-credentials">DNS 凭据</Button>
		  <Button color="inherit" component={RouterLink} to="/renewal-settings">自动续签</Button>
		  <Button color="inherit" component={RouterLink} to="/jobs">任务</Button>
		  <Button color="inherit" component={RouterLink} to="/audit-events">审计</Button>
		  <Button color="inherit" component={RouterLink} to="/system-info">系统</Button>
          <Typography color="text.secondary" variant="body2" sx={{ mr: 2 }}>{environment}</Typography>
          <Button color="inherit" startIcon={<LogoutOutlinedIcon />} onClick={() => signOut.mutate()} disabled={signOut.isPending}>退出</Button>
        </Toolbar>
      </AppBar>
      <Container maxWidth="lg" sx={{ py: 5 }}>
        <Typography color="text.secondary" sx={{ mb: 3 }}>欢迎，{currentUser.data.username}。</Typography>
        <Routes>
          <Route index element={<DashboardPage />} />
          <Route path="certificates" element={<CertificateListPage />} />
          <Route path="certificates/new" element={<CreateCertificatePage />} />
          <Route path="certificates/:id" element={<CertificateDetailPage />} />
          <Route path="dns-credentials" element={<DNSCredentialsPage />} />
		  <Route path="renewal-settings" element={<RenewalSettingsPage />} />
		  <Route path="jobs" element={<JobsPage />} />
		  <Route path="audit-events" element={<AuditPage />} />
		  <Route path="system-info" element={<SystemInfoPage />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </Container>
    </>
  )
}

function FullPageProgress() {
  return <Box sx={{ display: 'grid', minHeight: '100vh', placeItems: 'center' }}><CircularProgress /></Box>
}
