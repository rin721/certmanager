import AddOutlinedIcon from '@mui/icons-material/AddOutlined'
import ContentCopyOutlinedIcon from '@mui/icons-material/ContentCopyOutlined'
import DownloadOutlinedIcon from '@mui/icons-material/DownloadOutlined'
import VisibilityOutlinedIcon from '@mui/icons-material/VisibilityOutlined'
import AutorenewOutlinedIcon from '@mui/icons-material/AutorenewOutlined'
import { zodResolver } from '@hookform/resolvers/zod'
import {
  Alert,
  Box,
  Button,
  Card,
  CardContent,
  Checkbox,
  Chip,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  FormControlLabel,
  Link,
  MenuItem,
  Paper,
  Stack,
  Step,
  StepLabel,
  Stepper,
  Tab,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Tabs,
  TextField,
  Typography,
} from '@mui/material'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useEffect, useMemo, useState } from 'react'
import { useForm, useWatch } from 'react-hook-form'
import { Link as RouterLink, useNavigate, useParams } from 'react-router-dom'
import { z } from 'zod'
import {
	ApiError,
	auditPrivateKeyCopy,
	getDashboard,
  type Certificate,
  type CertificateFile,
  certificateDownloadURL,
  createACMECertificate,
  createSelfSignedCertificate,
	deleteCertificate,
  downloadCertificateArchive,
  getCertificate,
	getCertificateFile,
  issueCertificate,
  listCertificateFiles,
  listCertificates,
  listDNSCredentials,
  listJobs,
  revealPrivateKey,
  reauthenticate,
	revokeCertificate,
  renewCertificate,
  updateCertificate,
} from './api'
import { CertificateAudits, CertificateJobs, JobTable } from './OperationsPages'
import { isSafeCADirectoryURL } from './validation'

const formSchema = z.object({
  mode: z.enum(['self_signed', 'acme']),
  name: z.string().trim().min(1, '请输入证书名称').max(100),
  primary_domain: z.string().trim().min(1, '请输入主域名'),
  sans: z.string(),
  key_type: z.enum(['ec-256', 'rsa-2048', 'rsa-3072']),
  valid_days: z.number().int().min(1).max(3650),
  output_directory: z.string().trim().regex(/^$|^[a-z0-9][a-z0-9-]{0,62}$/, '只能使用小写字母、数字和连字符'),
  auto_renew_enabled: z.boolean(),
  renew_before_days: z.number().int().min(1).max(365),
  create_renewed_marker: z.boolean(),
  challenge_type: z.enum(['dns-01', 'http-01']),
  dns_credential_id: z.string(),
  ca_directory_url: z.string(),
  acme_email: z.string(),
}).superRefine((value, context) => {
  if (value.mode === 'acme') {
    if (!value.acme_email.includes('@')) context.addIssue({ code: 'custom', path: ['acme_email'], message: '请输入有效 ACME 邮箱' })
    if (!value.ca_directory_url.trim()) {
      context.addIssue({ code: 'custom', path: ['ca_directory_url'], message: '请选择或填写 ACME Directory URL' })
    } else if (!['letsencrypt', 'letsencrypt_test', 'zerossl'].includes(value.ca_directory_url) && !isSafeCADirectoryURL(value.ca_directory_url)) {
      context.addIssue({ code: 'custom', path: ['ca_directory_url'], message: '自定义地址必须是 HTTPS URL，且不能包含用户名、密码或片段' })
    }
    if (value.challenge_type === 'dns-01' && !value.dns_credential_id) context.addIssue({ code: 'custom', path: ['dns_credential_id'], message: 'DNS-01 必须选择凭据' })
  } else if (value.renew_before_days >= value.valid_days) {
    context.addIssue({ code: 'custom', path: ['renew_before_days'], message: '必须小于有效天数' })
  }
})

type FormValue = z.infer<typeof formSchema>

export function DashboardPage() {
	const query = useQuery({ queryKey: ['dashboard'], queryFn: getDashboard })
  if (query.isPending) return <Typography>正在加载证书统计…</Typography>
  if (query.isError) return <Alert severity="error">无法读取证书统计。</Alert>
  return (
    <Stack spacing={3}>
      <Stack direction={{ xs: 'column', sm: 'row' }} sx={{ justifyContent: 'space-between', gap: 2 }}>
        <Box><Typography variant="h4">仪表盘</Typography><Typography color="text.secondary">证书状态概览</Typography></Box>
        <Button component={RouterLink} to="/certificates/new" variant="contained" startIcon={<AddOutlinedIcon />}>创建证书</Button>
      </Stack>
      <Box sx={{ display: 'grid', gridTemplateColumns: { xs: '1fr 1fr', md: 'repeat(4, 1fr)' }, gap: 2 }}>
		{[["证书总数", query.data.counts.total], ["正常证书", query.data.counts.active], ["即将过期", query.data.counts.expiring], ["已过期", query.data.counts.expired], ["续签失败", query.data.counts.failed]].map(([label, value]) => (
          <Card variant="outlined" key={String(label)}><CardContent><Typography color="text.secondary">{label}</Typography><Typography variant="h4">{value}</Typography></CardContent></Card>
		))}
	  </Box>
	  <Typography variant="h6">最近任务</Typography><JobTable values={query.data.recent_jobs} />
	  <Typography variant="h6">最近即将过期的证书</Typography>{query.data.expiring_certificates.length ? <Stack>{query.data.expiring_certificates.map((item) => <Link key={item.id} component={RouterLink} to={`/certificates/${item.id}`}>{item.name} · {item.not_after ? new Date(item.not_after).toLocaleDateString() : '—'}</Link>)}</Stack> : <Typography color="text.secondary">未来 30 天没有即将过期的证书。</Typography>}
    </Stack>
  )
}

export function CertificateListPage() {
  const query = useQuery({ queryKey: ['certificates'], queryFn: listCertificates })
  const [search, setSearch] = useState('')
  const [status, setStatus] = useState('')
  const [modeFilter, setModeFilter] = useState('')
  const [expiryOrder, setExpiryOrder] = useState<'asc' | 'desc'>('asc')
  const [referenceNow] = useState(() => Date.now())
  const values = useMemo(() => (query.data ?? [])
    .filter((item) => !search || `${item.name} ${item.primary_domain} ${item.domains.join(' ')}`.toLowerCase().includes(search.toLowerCase()))
    .filter((item) => !status || item.status === status)
    .filter((item) => !modeFilter || item.mode === modeFilter)
    .sort((left, right) => {
      const leftTime = left.not_after ? Date.parse(left.not_after) : Number.MAX_SAFE_INTEGER
      const rightTime = right.not_after ? Date.parse(right.not_after) : Number.MAX_SAFE_INTEGER
      return expiryOrder === 'asc' ? leftTime - rightTime : rightTime - leftTime
    }), [expiryOrder, modeFilter, query.data, search, status])
  return (
    <Stack spacing={3}>
      <Stack direction={{ xs: 'column', sm: 'row' }} sx={{ justifyContent: 'space-between', gap: 2 }}>
        <Box><Typography variant="h4">证书</Typography><Typography color="text.secondary">查看证书模式、状态和有效期</Typography></Box>
        <Button component={RouterLink} to="/certificates/new" variant="contained" startIcon={<AddOutlinedIcon />}>创建证书</Button>
      </Stack>
      {query.isError && <Alert severity="error">读取证书列表失败。</Alert>}
      <Stack direction={{ xs: 'column', md: 'row' }} spacing={2}><TextField label="搜索名称或域名" value={search} onChange={(event) => setSearch(event.target.value)} /><TextField select label="状态" value={status} onChange={(event) => setStatus(event.target.value)} sx={{ minWidth: 150 }}><MenuItem value="">全部</MenuItem>{['pending', 'issuing', 'active', 'expiring', 'expired', 'renewing', 'failed', 'disabled', 'revoked'].map((value) => <MenuItem key={value} value={value}>{value}</MenuItem>)}</TextField><TextField select label="模式" value={modeFilter} onChange={(event) => setModeFilter(event.target.value)} sx={{ minWidth: 170 }}><MenuItem value="">全部</MenuItem><MenuItem value="acme">公共 CA</MenuItem><MenuItem value="self_signed">本地自签名</MenuItem></TextField><TextField select label="到期时间排序" value={expiryOrder} onChange={(event) => setExpiryOrder(event.target.value as 'asc' | 'desc')} sx={{ minWidth: 180 }}><MenuItem value="asc">最早到期优先</MenuItem><MenuItem value="desc">最晚到期优先</MenuItem></TextField></Stack>
       <TableContainer component={Paper} variant="outlined" sx={{ overflowX: 'auto' }}>
         <Table sx={{ minWidth: 960 }}>
          <TableHead><TableRow><TableCell>名称</TableCell><TableCell>主域名</TableCell><TableCell>SAN</TableCell><TableCell>模式</TableCell><TableCell>签发者 / 密钥</TableCell><TableCell>状态</TableCell><TableCell>到期 / 剩余</TableCell><TableCell>自动更新 / 最近续签</TableCell></TableRow></TableHead>
          <TableBody>
            {values.map((item) => (
              <TableRow key={item.id} hover>
                <TableCell><Link component={RouterLink} to={`/certificates/${item.id}`} underline="hover">{item.name}</Link></TableCell>
                <TableCell>{item.primary_domain}</TableCell><TableCell>{Math.max(0, item.domains.length - 1)}</TableCell><TableCell>{item.mode === 'acme' ? '公共 CA' : '本地自签名'}</TableCell>
                <TableCell>{item.issuer || '—'}<Typography variant="caption" sx={{ display: 'block' }} color="text.secondary">{item.key_type}</Typography></TableCell>
                <TableCell><StatusChip status={item.status} /></TableCell>
                <TableCell>{item.not_after ? new Date(item.not_after).toLocaleString() : '—'}<Typography variant="caption" sx={{ display: 'block' }} color="text.secondary">{remainingDays(item.not_after, referenceNow)} 天</Typography></TableCell>
                <TableCell>{item.auto_renew_enabled ? '开启' : '关闭'}<Typography variant="caption" sx={{ display: 'block' }} color="text.secondary">{item.last_renewed_at ? new Date(item.last_renewed_at).toLocaleString() : '尚未续签'}</Typography></TableCell>
              </TableRow>
            ))}
            {!query.isPending && values.length === 0 && <TableRow><TableCell colSpan={8} align="center">没有符合条件的证书</TableCell></TableRow>}
          </TableBody>
        </Table>
      </TableContainer>
    </Stack>
  )
}

function remainingDays(notAfter: string | undefined, now: number): number | string {
  if (!notAfter) return '—'
  return Math.ceil((Date.parse(notAfter) - now) / 86_400_000)
}

export function CreateCertificatePage() {
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const [activeStep, setActiveStep] = useState(0)
  const credentials = useQuery({ queryKey: ['dns-credentials'], queryFn: listDNSCredentials })
  const form = useForm<FormValue>({
    resolver: zodResolver(formSchema),
    defaultValues: {
      mode: 'self_signed', name: '', primary_domain: '', sans: '', key_type: 'ec-256', valid_days: 365,
      output_directory: '', auto_renew_enabled: true, renew_before_days: 30, create_renewed_marker: true,
      challenge_type: 'dns-01', dns_credential_id: '', ca_directory_url: 'letsencrypt', acme_email: '',
    },
  })
  const mode = useWatch({ control: form.control, name: 'mode' })
  const challengeType = useWatch({ control: form.control, name: 'challenge_type' })
  const caDirectoryURL = useWatch({ control: form.control, name: 'ca_directory_url' })
  const mutation = useMutation({
    mutationFn: (value: FormValue) => {
      const common = {
        name: value.name, primary_domain: value.primary_domain,
        sans: value.sans.split(/[\n,]/).map((item) => item.trim()).filter(Boolean), key_type: value.key_type,
        output_directory: value.output_directory, auto_renew_enabled: value.auto_renew_enabled,
        renew_before_days: value.renew_before_days, create_renewed_marker: value.create_renewed_marker,
      }
      return value.mode === 'acme'
        ? createACMECertificate({ ...common, mode: 'acme', challenge_type: value.challenge_type, dns_credential_id: value.dns_credential_id, ca_directory_url: value.ca_directory_url, acme_email: value.acme_email })
        : createSelfSignedCertificate({ ...common, mode: 'self_signed', valid_days: value.valid_days })
    },
    onSuccess: async (certificate) => {
      await queryClient.invalidateQueries({ queryKey: ['certificates'] })
      await navigate(`/certificates/${certificate.id}`, { replace: true })
    },
  })
  const steps = ['证书类型', '域名', '签发配置', '输出和续签', '确认']
  const advance = async () => {
    const fields: Array<Array<keyof FormValue>> = [
      ['mode'], ['name', 'primary_domain', 'sans'],
      mode === 'acme' ? ['key_type', 'challenge_type', 'dns_credential_id', 'ca_directory_url', 'acme_email'] : ['key_type', 'valid_days'],
      ['output_directory', 'auto_renew_enabled', 'renew_before_days', 'create_renewed_marker'],
    ]
    if (await form.trigger(fields[activeStep])) setActiveStep((step) => Math.min(step + 1, steps.length - 1))
  }
  return (
	<Stack spacing={3} component="form" onSubmit={(event) => {
	  event.preventDefault()
	  if (activeStep < steps.length - 1) {
		void advance()
	  }
	}}>
      <Box><Typography variant="h4">创建证书</Typography><Typography color="text.secondary">按步骤完成类型、域名、签发和输出配置</Typography></Box>
      <Stepper activeStep={activeStep} alternativeLabel>{steps.map((label) => <Step key={label}><StepLabel>{label}</StepLabel></Step>)}</Stepper>
      {mode === 'self_signed' && <Alert severity="warning">自签名证书不会被浏览器、Outlook、手机邮件客户端或操作系统默认信任，仅适用于内网、开发和测试环境。</Alert>}
      {mutation.isError && <Alert severity="error">{mutation.error instanceof ApiError ? mutation.error.message : '创建失败'}</Alert>}
      <Card variant="outlined"><CardContent><Stack spacing={2.5}>
		{activeStep === 0 && <Stack direction={{ xs: 'column', sm: 'row' }} spacing={2}><Button type="button" size="large" variant={mode === 'acme' ? 'contained' : 'outlined'} onClick={() => form.setValue('mode', 'acme')}>公共 CA 证书</Button><Button type="button" size="large" variant={mode === 'self_signed' ? 'contained' : 'outlined'} onClick={() => form.setValue('mode', 'self_signed')}>本地自签名证书</Button></Stack>}
        {activeStep === 1 && <><TextField label="证书名称" error={Boolean(form.formState.errors.name)} helperText={form.formState.errors.name?.message} {...form.register('name')} /><TextField label="主域名" placeholder="example.com" error={Boolean(form.formState.errors.primary_domain)} helperText={form.formState.errors.primary_domain?.message} {...form.register('primary_domain')} /><TextField label="SAN 域名" placeholder={'www.example.com\n*.example.com'} multiline minRows={3} helperText="每行一个，或使用逗号分隔；主域名会自动包含" {...form.register('sans')} /></>}
        {activeStep === 2 && <><TextField select label="密钥类型" {...form.register('key_type')}><MenuItem value="ec-256">ECDSA P-256（推荐）</MenuItem><MenuItem value="rsa-2048">RSA 2048</MenuItem><MenuItem value="rsa-3072">RSA 3072</MenuItem></TextField>{mode === 'self_signed' ? <TextField label="有效天数" type="number" error={Boolean(form.formState.errors.valid_days)} helperText={form.formState.errors.valid_days?.message} {...form.register('valid_days', { valueAsNumber: true })} /> : <><TextField select label="ACME CA" value={['letsencrypt', 'letsencrypt_test', 'zerossl'].includes(caDirectoryURL) ? caDirectoryURL : (caDirectoryURL ? 'custom' : '')} onChange={(event) => form.setValue('ca_directory_url', event.target.value === 'custom' ? '' : event.target.value, { shouldValidate: true })} error={Boolean(form.formState.errors.ca_directory_url)} helperText={form.formState.errors.ca_directory_url?.message}><MenuItem value="">请选择</MenuItem><MenuItem value="letsencrypt">Let’s Encrypt 正式环境</MenuItem><MenuItem value="letsencrypt_test">Let’s Encrypt Staging</MenuItem><MenuItem value="zerossl">ZeroSSL</MenuItem><MenuItem value="custom">自定义 Directory URL</MenuItem></TextField>{(!['letsencrypt', 'letsencrypt_test', 'zerossl'].includes(caDirectoryURL)) && <TextField label="自定义 ACME Directory URL" placeholder="https://acme.example.com/directory" error={Boolean(form.formState.errors.ca_directory_url)} helperText={form.formState.errors.ca_directory_url?.message || '仅支持 HTTPS；不会保存或发送 URL 中的凭据'} {...form.register('ca_directory_url')} />}<TextField label="ACME 邮箱" type="email" error={Boolean(form.formState.errors.acme_email)} helperText={form.formState.errors.acme_email?.message} {...form.register('acme_email')} /><TextField select label="验证方式" {...form.register('challenge_type')}><MenuItem value="dns-01">DNS-01（推荐）</MenuItem><MenuItem value="http-01">HTTP-01</MenuItem></TextField>{challengeType === 'dns-01' && <TextField select label="DNS 凭据" error={Boolean(form.formState.errors.dns_credential_id)} helperText={form.formState.errors.dns_credential_id?.message || (credentials.data?.length ? '' : '请先在 DNS 凭据页面创建凭据')} {...form.register('dns_credential_id')}>{credentials.data?.map((item) => <MenuItem key={item.id} value={item.id}>{item.name}</MenuItem>)}</TextField>}</>}</>}
        {activeStep === 3 && <><TextField label="安全输出目录名" placeholder="留空时根据主域名生成" error={Boolean(form.formState.errors.output_directory)} helperText={form.formState.errors.output_directory?.message} {...form.register('output_directory')} /><TextField label="提前续签/重新生成天数" type="number" error={Boolean(form.formState.errors.renew_before_days)} helperText={form.formState.errors.renew_before_days?.message} {...form.register('renew_before_days', { valueAsNumber: true })} /><FormControlLabel control={<Checkbox defaultChecked {...form.register('auto_renew_enabled')} />} label="自动续签或重新生成" /><FormControlLabel control={<Checkbox defaultChecked {...form.register('create_renewed_marker')} />} label="更新后创建 .renewed 标记文件" /></>}
        {activeStep === 4 && <Stack spacing={1}><Typography><b>类型：</b>{mode === 'acme' ? '公共 CA 证书' : '本地自签名证书'}</Typography><Typography><b>名称：</b>{form.getValues('name')}</Typography><Typography><b>主域名：</b>{form.getValues('primary_domain')}</Typography><Typography><b>密钥：</b>{form.getValues('key_type')}</Typography><Typography><b>输出：</b>/certs/{form.getValues('output_directory') || '（根据域名生成）'}</Typography>{mode === 'acme' && <Typography color="text.secondary">DNS 敏感值不会在确认页显示。</Typography>}</Stack>}
      </Stack></CardContent></Card>
	  <Stack direction="row" spacing={2}>{activeStep > 0 && <Button type="button" onClick={() => setActiveStep((step) => step - 1)}>上一步</Button>}{activeStep < steps.length - 1 ? <Button type="button" variant="contained" onClick={advance}>下一步</Button> : <Button type="button" variant="contained" disabled={mutation.isPending} onClick={() => { void form.handleSubmit((value) => mutation.mutate(value))() }}>{mutation.isPending ? '正在签发…' : '确认并创建'}</Button>}<Button component={RouterLink} to="/certificates">取消</Button></Stack>
    </Stack>
  )
}

export function CertificateDetailPage() {
  const { id = '' } = useParams()
	const navigate = useNavigate()
  const queryClient = useQueryClient()
  const [tab, setTab] = useState(0)
  const [forceOpen, setForceOpen] = useState(false)
  const [forcePassword, setForcePassword] = useState('')
	const [revokeOpen, setRevokeOpen] = useState(false)
	const [revokePassword, setRevokePassword] = useState('')
	const [deleteOpen, setDeleteOpen] = useState(false)
	const [deletePassword, setDeletePassword] = useState('')
	const [deleteName, setDeleteName] = useState('')
	const [deleteFiles, setDeleteFiles] = useState(false)
  const query = useQuery({ queryKey: ['certificate', id], queryFn: () => getCertificate(id), enabled: Boolean(id) })
  const renew = useMutation({
    mutationFn: () => renewCertificate(id),
    onSuccess: (value) => { queryClient.setQueryData(['certificate', id], value); void queryClient.invalidateQueries({ queryKey: ['certificates'] }) },
  })
  const forceRenew = useMutation({
    mutationFn: async () => { await reauthenticate(forcePassword); return renewCertificate(id, true) },
    onSuccess: (value) => { setForcePassword(''); setForceOpen(false); queryClient.setQueryData(['certificate', id], value); void queryClient.invalidateQueries({ queryKey: ['certificates'] }) },
  })
	const issue = useMutation({
	  mutationFn: () => issueCertificate(id),
	  onSuccess: (value) => { queryClient.setQueryData(['certificate', id], value); void queryClient.invalidateQueries({ queryKey: ['certificates'] }) },
	})
	const revoke = useMutation({
	  mutationFn: () => revokeCertificate(id, revokePassword),
	  onSuccess: (value) => { setRevokePassword(''); setRevokeOpen(false); queryClient.setQueryData(['certificate', id], value); void queryClient.invalidateQueries({ queryKey: ['certificates'] }) },
	})
	const remove = useMutation({
	  mutationFn: () => deleteCertificate(id, deletePassword, deleteName, deleteFiles),
	  onSuccess: async () => { setDeletePassword(''); setDeleteName(''); setDeleteOpen(false); await queryClient.invalidateQueries({ queryKey: ['certificates'] }); await navigate('/certificates', { replace: true }) },
	})
  if (query.isPending) return <Typography>正在加载证书…</Typography>
  if (query.isError) return <Alert severity="error">证书不存在或读取失败。</Alert>
  const certificate = query.data
	const canIssue = ['pending', 'failed', 'active', 'expiring', 'expired'].includes(certificate.status)
  return (
    <Stack spacing={3}>
      <Stack direction={{ xs: 'column', md: 'row' }} sx={{ justifyContent: 'space-between', gap: 2 }}><Box><Typography variant="h4">{certificate.name}</Typography><Stack direction="row" spacing={1} sx={{ mt: 1 }}><StatusChip status={certificate.status} /><Chip label={certificate.mode === 'acme' ? '公共 CA 证书' : '本地自签名证书'} variant="outlined" /></Stack></Box><Stack direction={{ xs: 'column', sm: 'row' }} spacing={1}><Button startIcon={<AutorenewOutlinedIcon />} variant="outlined" disabled={renew.isPending} onClick={() => renew.mutate()}>手动续签</Button><Button variant="outlined" disabled={!canIssue || issue.isPending} onClick={() => issue.mutate()}>{issue.isPending ? '正在签发…' : certificate.status === 'failed' ? '重试签发' : '重新签发'}</Button><Button color="warning" disabled={forceRenew.isPending} onClick={() => setForceOpen(true)}>强制续签</Button>{certificate.mode === 'acme' && <Button color="warning" onClick={() => setRevokeOpen(true)}>撤销</Button>}<Button color="error" onClick={() => setDeleteOpen(true)}>删除</Button></Stack></Stack>
      {(renew.isError || forceRenew.isError || issue.isError || revoke.isError || remove.isError) && <Alert severity="error">操作失败，请检查确认信息并查看任务日志。</Alert>}
      <Paper variant="outlined"><Tabs value={tab} onChange={(_, value: number) => setTab(value)} variant="scrollable"><Tab label="概览" /><Tab label="域名" /><Tab label="证书文件" /><Tab label="自动续签" /><Tab label="任务历史" /><Tab label="审计记录" /></Tabs></Paper>
      {tab === 0 && <Overview certificate={certificate} />}
      {tab === 1 && <Card variant="outlined"><CardContent><Stack spacing={1}>{certificate.domains.map((domain) => <Typography key={domain} component="code">{domain}</Typography>)}</Stack></CardContent></Card>}
      {tab === 2 && <CertificateFiles certificate={certificate} />}
      {tab === 3 && <RenewalSettings certificate={certificate} onUpdated={(value) => { queryClient.setQueryData(['certificate', id], value); void queryClient.invalidateQueries({ queryKey: ['certificates'] }) }} />}
	  {tab === 4 && <CertificateJobs certificateId={certificate.id} />}
	  {tab === 5 && <CertificateAudits certificateId={certificate.id} />}
      <Dialog open={forceOpen} onClose={() => { setForceOpen(false); setForcePassword('') }}><DialogTitle>确认强制续签</DialogTitle><DialogContent><Alert severity="warning" sx={{ mb: 2 }}>强制续签可能触发 CA 速率限制。普通自动任务永远不会使用 --force。</Alert><TextField label="管理员密码" type="password" fullWidth value={forcePassword} onChange={(event) => setForcePassword(event.target.value)} /></DialogContent><DialogActions><Button onClick={() => { setForceOpen(false); setForcePassword('') }}>取消</Button><Button color="warning" variant="contained" disabled={!forcePassword || forceRenew.isPending} onClick={() => forceRenew.mutate()}>确认强制续签</Button></DialogActions></Dialog>
	  <Dialog open={revokeOpen} onClose={() => { setRevokeOpen(false); setRevokePassword('') }}><DialogTitle>确认撤销公共证书</DialogTitle><DialogContent><Alert severity="warning" sx={{ mb: 2 }}>撤销会通知 CA 将证书标记为不再可信，无法撤销此操作。</Alert><TextField label="管理员密码" type="password" autoComplete="current-password" fullWidth value={revokePassword} onChange={(event) => setRevokePassword(event.target.value)} /></DialogContent><DialogActions><Button onClick={() => { setRevokeOpen(false); setRevokePassword('') }}>取消</Button><Button color="warning" variant="contained" disabled={!revokePassword || revoke.isPending} onClick={() => revoke.mutate()}>确认撤销</Button></DialogActions></Dialog>
	  <Dialog open={deleteOpen} onClose={() => { setDeleteOpen(false); setDeletePassword(''); setDeleteName('') }}><DialogTitle>删除证书</DialogTitle><DialogContent><Alert severity="error" sx={{ mb: 2 }}>删除管理记录不可撤销。选择删除文件时，系统会先保存短期备份。</Alert><Stack spacing={2}><TextField label={`输入证书名称 ${certificate.name} 以确认`} value={deleteName} onChange={(event) => setDeleteName(event.target.value)} /><TextField label="管理员密码" type="password" autoComplete="current-password" value={deletePassword} onChange={(event) => setDeletePassword(event.target.value)} /><FormControlLabel control={<Checkbox checked={deleteFiles} onChange={(event) => setDeleteFiles(event.target.checked)} />} label="同时删除证书文件（先创建备份）" /></Stack></DialogContent><DialogActions><Button onClick={() => { setDeleteOpen(false); setDeletePassword(''); setDeleteName('') }}>取消</Button><Button color="error" variant="contained" disabled={deleteName !== certificate.name || !deletePassword || remove.isPending} onClick={() => remove.mutate()}>确认删除</Button></DialogActions></Dialog>
    </Stack>
  )
}

function RenewalSettings({ certificate, onUpdated }: { certificate: Certificate; onUpdated: (value: Certificate) => void }) {
  const [name, setName] = useState(certificate.name)
  const [enabled, setEnabled] = useState(certificate.auto_renew_enabled)
  const [days, setDays] = useState(certificate.renew_before_days)
  const [marker, setMarker] = useState(certificate.create_renewed_marker)
  const mutation = useMutation({
    mutationFn: () => updateCertificate(certificate.id, { name, auto_renew_enabled: enabled, renew_before_days: days, create_renewed_marker: marker }),
    onSuccess: onUpdated,
  })
  return <Card variant="outlined"><CardContent><Stack spacing={2}><Typography variant="h6">证书与续签设置</Typography>{mutation.isSuccess && <Alert severity="success">设置已保存，下一次调度检查立即使用新值。</Alert>}{mutation.isError && <Alert severity="error">设置无效或保存失败。</Alert>}<TextField label="显示名称" value={name} onChange={(event) => setName(event.target.value)} /><TextField label="提前续签/重新生成天数" type="number" value={days} slotProps={{ htmlInput: { min: 1, max: 365 } }} onChange={(event) => setDays(Number(event.target.value))} /><FormControlLabel control={<Checkbox checked={enabled} onChange={(event) => setEnabled(event.target.checked)} />} label="启用自动续签或重新生成" /><FormControlLabel control={<Checkbox checked={marker} onChange={(event) => setMarker(event.target.checked)} />} label="更新后创建 .renewed 标记文件" /><Button variant="contained" sx={{ alignSelf: 'flex-start' }} disabled={!name.trim() || days < 1 || days > 365 || mutation.isPending} onClick={() => mutation.mutate()}>保存设置</Button></Stack></CardContent></Card>
}

function Overview({ certificate }: { certificate: Certificate }) {
  const jobs = useQuery({ queryKey: ['jobs', certificate.id, 'overview'], queryFn: () => listJobs({ certificateId: certificate.id }) })
  const [referenceNow] = useState(() => Date.now())
  const rows = useMemo(() => [
    ['Subject', `CN=${certificate.primary_domain}`], ['主域名', certificate.primary_domain], ['SAN', certificate.domains.join(', ')], ['签发者', certificate.issuer || '—'], ['序列号', certificate.serial_number || '—'],
    ['生效时间', certificate.not_before ? new Date(certificate.not_before).toLocaleString() : '—'],
    ['到期时间', certificate.not_after ? new Date(certificate.not_after).toLocaleString() : '—'],
    ['剩余天数', remainingDays(certificate.not_after, referenceNow)],
    ['SHA-256 指纹', certificate.fingerprint_sha256 || '—'], ['密钥类型', certificate.key_type],
    ['容器内目录', `/certs/${certificate.output_directory}`],
    ['最近任务结果', jobs.data?.[0] ? `${jobs.data[0].job_type} · ${jobs.data[0].status}` : '尚无任务'],
  ], [certificate, jobs.data, referenceNow])
  return <Card variant="outlined"><CardContent><Table size="small"><TableBody>{rows.map(([label, value]) => <TableRow key={label}><TableCell sx={{ width: 180, color: 'text.secondary' }}>{label}</TableCell><TableCell sx={{ wordBreak: 'break-all' }}>{value}</TableCell></TableRow>)}</TableBody></Table></CardContent></Card>
}

function CertificateFiles({ certificate }: { certificate: Certificate }) {
  const files = useQuery({ queryKey: ['certificate-files', certificate.id], queryFn: () => listCertificateFiles(certificate.id) })
  const [selected, setSelected] = useState<CertificateFile | null>(null)
  const [content, setContent] = useState('')
  const [passwordOpen, setPasswordOpen] = useState(false)
  const [password, setPassword] = useState('')
  const [archivePasswordOpen, setArchivePasswordOpen] = useState(false)
  const [error, setError] = useState('')
  const load = useMutation({
    mutationFn: (file: CertificateFile) => getCertificateFile(certificate.id, file.type),
    onSuccess: (value, file) => { setSelected(file); setContent(value); setError('') },
    onError: () => setError('读取证书文件失败。'),
  })
  const reveal = useMutation({
    mutationFn: () => revealPrivateKey(certificate.id, password),
    onSuccess: (value) => {
      const file = files.data?.find((item) => item.private) ?? null
      setSelected(file); setContent(value); setPassword(''); setPasswordOpen(false); setError('')
    },
    onError: () => setError('管理员密码错误或重新认证失败。'),
  })
  const archive = useMutation({
    mutationFn: (includePrivateKey: boolean) => downloadCertificateArchive(certificate.id, includePrivateKey, includePrivateKey ? password : ''),
    onSuccess: () => { setPassword(''); setArchivePasswordOpen(false); setError('') },
    onError: () => setError('压缩包下载失败或管理员密码错误。'),
  })
  useEffect(() => () => { setContent(''); setPassword('') }, [])
  useEffect(() => {
    if (selected?.private && content) {
      const timeout = window.setTimeout(() => { setContent(''); setSelected(null) }, 120_000)
      return () => window.clearTimeout(timeout)
    }
    return undefined
  }, [content, selected])
  const closeViewer = () => { setContent(''); setSelected(null) }
  return (
    <Stack spacing={2}>
      {error && <Alert severity="error">{error}</Alert>}
      <Alert severity="info">容器内目录为 /certs/{certificate.output_directory}；宿主机路径为 compose 中 CERTS_HOST_DIR 对应目录下的 {certificate.output_directory}。其他容器应只读挂载该宿主机目录。</Alert>
      <Stack direction={{ xs: 'column', sm: 'row' }} spacing={1}><Button variant="outlined" startIcon={<DownloadOutlinedIcon />} disabled={archive.isPending} onClick={() => archive.mutate(false)}>下载 ZIP（不含私钥）</Button><Button color="warning" variant="outlined" startIcon={<DownloadOutlinedIcon />} onClick={() => setArchivePasswordOpen(true)}>下载 ZIP（含私钥）</Button></Stack>
       <TableContainer component={Paper} variant="outlined" sx={{ overflowX: 'auto' }}><Table sx={{ minWidth: 640 }}><TableHead><TableRow><TableCell>文件</TableCell><TableCell>容器内路径</TableCell><TableCell align="right">操作</TableCell></TableRow></TableHead><TableBody>
        {files.data?.map((file) => <TableRow key={file.type}><TableCell>{file.filename}{file.private && <Chip label="高风险" color="warning" size="small" sx={{ ml: 1 }} />}</TableCell><TableCell component="code">{file.container_path}</TableCell><TableCell align="right"><Button startIcon={<VisibilityOutlinedIcon />} onClick={() => file.private ? setPasswordOpen(true) : load.mutate(file)}>查看</Button><Button component="a" href={certificateDownloadURL(certificate.id, file.type)} startIcon={<DownloadOutlinedIcon />} disabled={file.private && selected?.type !== 'private-key'}>下载</Button></TableCell></TableRow>)}
      </TableBody></Table></TableContainer>
      <Dialog open={Boolean(selected && content)} onClose={closeViewer} maxWidth="md" fullWidth><DialogTitle>{selected?.filename}</DialogTitle><DialogContent><Alert severity={selected?.private ? 'warning' : 'info'} sx={{ mb: 2 }}>{selected?.private ? '私钥属于高敏感信息。关闭窗口或离开页面后将立即从前端内存清除。' : '证书内容可以安全复制给需要使用它的服务。'}</Alert><Box component="pre" sx={{ bgcolor: 'grey.950', color: 'grey.100', p: 2, borderRadius: 1, maxHeight: '50vh', overflow: 'auto', whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>{content}</Box></DialogContent><DialogActions><Button startIcon={<ContentCopyOutlinedIcon />} onClick={async () => { await copyText(content); if (selected?.private) await auditPrivateKeyCopy(certificate.id) }}>复制</Button><Button onClick={closeViewer}>关闭</Button></DialogActions></Dialog>
      <Dialog open={passwordOpen} onClose={() => { setPassword(''); setPasswordOpen(false) }}><DialogTitle>重新认证以查看私钥</DialogTitle><DialogContent><Alert severity="warning" sx={{ mb: 2 }}>私钥一旦泄露，证书保护的服务将不再安全。此操作会被审计。</Alert><TextField label="管理员密码" type="password" autoComplete="current-password" fullWidth value={password} onChange={(event) => setPassword(event.target.value)} /></DialogContent><DialogActions><Button onClick={() => { setPassword(''); setPasswordOpen(false) }}>取消</Button><Button variant="contained" color="warning" disabled={!password || reveal.isPending} onClick={() => reveal.mutate()}>确认查看</Button></DialogActions></Dialog>
      <Dialog open={archivePasswordOpen} onClose={() => { setPassword(''); setArchivePasswordOpen(false) }}><DialogTitle>下载包含私钥的 ZIP</DialogTitle><DialogContent><Alert severity="warning" sx={{ mb: 2 }}>压缩包包含未加密的 privkey.pem。请仅保存到受控设备并限制文件权限；此操作会被审计。</Alert><TextField label="管理员密码" type="password" autoComplete="current-password" fullWidth value={password} onChange={(event) => setPassword(event.target.value)} /></DialogContent><DialogActions><Button onClick={() => { setPassword(''); setArchivePasswordOpen(false) }}>取消</Button><Button variant="contained" color="warning" disabled={!password || archive.isPending} onClick={() => archive.mutate(true)}>确认下载</Button></DialogActions></Dialog>
    </Stack>
  )
}

function StatusChip({ status }: { status: string }) {
  const color = status === 'active' ? 'success' : status === 'failed' ? 'error' : 'default'
  return <Chip label={status} color={color} size="small" />
}

async function copyText(value: string) {
  if (navigator.clipboard?.writeText) {
    await navigator.clipboard.writeText(value)
    return
  }
  const textarea = document.createElement('textarea')
  textarea.value = value
  textarea.style.position = 'fixed'
  textarea.style.opacity = '0'
  document.body.appendChild(textarea)
  textarea.select()
  document.execCommand('copy')
  textarea.remove()
}
