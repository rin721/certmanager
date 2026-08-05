import {
  Alert,
  Box,
  Card,
  CardContent,
  Chip,
  MenuItem,
  Paper,
  Stack,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  TextField,
  Typography,
} from '@mui/material'
import { useQuery } from '@tanstack/react-query'
import { useState } from 'react'
import {
  getSystemInfo,
  listCertificates,
  listAuditEvents,
  listJobs,
  type AuditEvent,
  type JobRun,
} from './api'

export function JobsPage() {
  const [status, setStatus] = useState('')
  const [jobType, setJobType] = useState('')
  const [certificateId, setCertificateId] = useState('')
  const [timeRange, setTimeRange] = useState('')
  const certificates = useQuery({ queryKey: ['certificates'], queryFn: listCertificates })
  const query = useQuery({ queryKey: ['jobs', status, jobType, certificateId, timeRange], queryFn: () => listJobs({ status, jobType, certificateId, since: timeRange ? new Date(Date.now() - Number(timeRange) * 86_400_000).toISOString() : '' }) })
  return (
    <Stack spacing={3}>
      <Box><Typography variant="h4">任务日志</Typography><Typography color="text.secondary">查看签发、续签和重新生成任务的脱敏输出</Typography></Box>
      <Stack direction={{ xs: 'column', sm: 'row' }} spacing={2}>
        <TextField select label="状态" value={status} onChange={(event) => setStatus(event.target.value)} sx={{ minWidth: 180 }}><MenuItem value="">全部</MenuItem>{['pending', 'running', 'succeeded', 'failed', 'interrupted', 'cancelled'].map((value) => <MenuItem key={value} value={value}>{value}</MenuItem>)}</TextField>
        <TextField select label="类型" value={jobType} onChange={(event) => setJobType(event.target.value)} sx={{ minWidth: 220 }}><MenuItem value="">全部</MenuItem>{['issue', 'renew', 'force_renew', 'self_signed_generate', 'revoke'].map((value) => <MenuItem key={value} value={value}>{value}</MenuItem>)}</TextField>
        <TextField select label="证书" value={certificateId} onChange={(event) => setCertificateId(event.target.value)} sx={{ minWidth: 220 }}><MenuItem value="">全部</MenuItem>{certificates.data?.map((value) => <MenuItem key={value.id} value={value.id}>{value.name}</MenuItem>)}</TextField>
        <TextField select label="时间范围" value={timeRange} onChange={(event) => setTimeRange(event.target.value)} sx={{ minWidth: 160 }}><MenuItem value="">全部</MenuItem><MenuItem value="1">最近 24 小时</MenuItem><MenuItem value="7">最近 7 天</MenuItem><MenuItem value="30">最近 30 天</MenuItem></TextField>
      </Stack>
      {query.isError ? <Alert severity="error">读取任务日志失败。</Alert> : <JobTable values={query.data ?? []} loading={query.isPending} />}
    </Stack>
  )
}

export function AuditPage() {
  const query = useQuery({ queryKey: ['audit-events'], queryFn: () => listAuditEvents() })
  return <Stack spacing={3}><Box><Typography variant="h4">审计记录</Typography><Typography color="text.secondary">敏感操作只记录元数据，不记录密码、令牌或私钥</Typography></Box>{query.isError ? <Alert severity="error">读取审计记录失败。</Alert> : <AuditTable values={query.data ?? []} loading={query.isPending} />}</Stack>
}

export function SystemInfoPage() {
  const query = useQuery({ queryKey: ['system-info'], queryFn: getSystemInfo, refetchInterval: 30_000 })
  if (query.isPending) return <Typography>正在读取系统信息…</Typography>
  if (query.isError) return <Alert severity="error">读取系统信息失败。</Alert>
  const value = query.data
  const rows = [
    ['应用版本', value.application_version], ['Go 版本', value.go_version], ['acme.sh 版本', value.acme_sh_version],
    ['OpenSSL 版本', value.openssl_version], ['SQLite 状态', value.sqlite_status], ['数据目录', value.data_directory],
    ['证书目录', value.certificate_directory], ['当前时区', value.timezone], ['调度器', value.scheduler.running ? '运行中' : '已停止'],
    ['最近调度时间', value.scheduler.last_run_at ? new Date(value.scheduler.last_run_at).toLocaleString() : '尚未运行'],
    ['下次调度时间', value.scheduler.next_run_at ? new Date(value.scheduler.next_run_at).toLocaleString() : '未安排'],
  ]
  return <Stack spacing={3}><Box><Typography variant="h4">系统信息</Typography><Typography color="text.secondary">运行状态与工具版本；本页永不显示 Secret</Typography></Box><Card variant="outlined"><CardContent><Table size="small"><TableBody>{rows.map(([label, content]) => <TableRow key={label}><TableCell sx={{ width: 200, color: 'text.secondary' }}>{label}</TableCell><TableCell component="code">{content}</TableCell></TableRow>)}</TableBody></Table></CardContent></Card></Stack>
}

export function CertificateJobs({ certificateId }: { certificateId: string }) {
  const query = useQuery({ queryKey: ['jobs', certificateId], queryFn: () => listJobs({ certificateId }) })
  return query.isError ? <Alert severity="error">读取任务历史失败。</Alert> : <JobTable values={query.data ?? []} loading={query.isPending} />
}

export function CertificateAudits({ certificateId }: { certificateId: string }) {
  const query = useQuery({ queryKey: ['audit-events', certificateId], queryFn: () => listAuditEvents(certificateId) })
  return query.isError ? <Alert severity="error">读取审计记录失败。</Alert> : <AuditTable values={query.data ?? []} loading={query.isPending} />
}

export function JobTable({ values, loading }: { values: JobRun[]; loading?: boolean }) {
  return <TableContainer component={Paper} variant="outlined"><Table><TableHead><TableRow><TableCell>开始时间</TableCell><TableCell>类型</TableCell><TableCell>状态</TableCell><TableCell>尝试</TableCell><TableCell>脱敏输出</TableCell></TableRow></TableHead><TableBody>{values.map((value) => <TableRow key={value.id}><TableCell>{new Date(value.started_at).toLocaleString()}</TableCell><TableCell>{value.job_type}</TableCell><TableCell><Chip size="small" label={value.status} color={value.status === 'succeeded' ? 'success' : value.status === 'failed' ? 'error' : 'default'} /></TableCell><TableCell>{value.attempt}</TableCell><TableCell><Box component="pre" sx={{ m: 0, maxWidth: 420, maxHeight: 120, overflow: 'auto', whiteSpace: 'pre-wrap' }}>{value.error_message || value.sanitized_output || '—'}</Box></TableCell></TableRow>)}{!loading && values.length === 0 && <TableRow><TableCell colSpan={5} align="center">暂无任务记录</TableCell></TableRow>}</TableBody></Table></TableContainer>
}

export function AuditTable({ values, loading }: { values: AuditEvent[]; loading?: boolean }) {
  return <TableContainer component={Paper} variant="outlined"><Table><TableHead><TableRow><TableCell>时间</TableCell><TableCell>事件</TableCell><TableCell>操作者</TableCell><TableCell>来源 IP</TableCell><TableCell>结果</TableCell></TableRow></TableHead><TableBody>{values.map((value) => <TableRow key={value.id}><TableCell>{new Date(value.created_at).toLocaleString()}</TableCell><TableCell>{value.event_type}</TableCell><TableCell>{value.actor}</TableCell><TableCell>{value.client_ip || '—'}</TableCell><TableCell>{value.result}</TableCell></TableRow>)}{!loading && values.length === 0 && <TableRow><TableCell colSpan={5} align="center">暂无审计记录</TableCell></TableRow>}</TableBody></Table></TableContainer>
}
