import PlayArrowOutlinedIcon from '@mui/icons-material/PlayArrowOutlined'
import SaveOutlinedIcon from '@mui/icons-material/SaveOutlined'
import {
  Alert,
  Button,
  Card,
  CardContent,
  Checkbox,
  FormControlLabel,
  MenuItem,
  Stack,
  TextField,
  Typography,
} from '@mui/material'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import { type RenewalPolicy, type SchedulerStatus, getRenewalPolicy, runRenewalNow, updateRenewalPolicy } from './api'

export function RenewalSettingsPage() {
  const query = useQuery({ queryKey: ['renewal-policy'], queryFn: getRenewalPolicy })
  if (query.isPending) return <Typography>正在加载续签策略…</Typography>
  if (query.isError) return <Alert severity="error">读取续签策略失败。</Alert>
  return <RenewalPolicyEditor initialPolicy={query.data.policy} status={query.data.status} />
}

function RenewalPolicyEditor({ initialPolicy, status }: { initialPolicy: RenewalPolicy; status: SchedulerStatus }) {
  const client = useQueryClient()
  const [policy, setPolicy] = useState(initialPolicy)
  const [mode, setMode] = useState(() => presetFor(initialPolicy.cron_expression))
  const [dailyTime, setDailyTime] = useState(() => dailyTimeFor(initialPolicy.cron_expression) ?? '04:00')
  const save = useMutation({
    mutationFn: () => updateRenewalPolicy(policy),
    onSuccess: (value) => client.setQueryData(['renewal-policy'], value),
  })
  const run = useMutation({
    mutationFn: runRenewalNow,
    onSuccess: () => client.invalidateQueries({ queryKey: ['renewal-policy'] }),
  })
  const selectPreset = (value: string) => {
    setMode(value)
    const cron = value === 'daily' ? '0 3 * * *' : value === '12h' ? '0 */12 * * *' : value === '6h' ? '0 */6 * * *' : value === 'custom_daily' ? cronForDailyTime(dailyTime) : policy.cron_expression
    setPolicy((current) => ({ ...current, cron_expression: cron }))
  }
  return (
    <Stack spacing={3}>
      <div><Typography variant="h4">自动续签设置</Typography><Typography color="text.secondary">保存后立即热更新，无需重启容器</Typography></div>
      {save.isError && <Alert severity="error">策略无效或热更新失败，旧调度仍继续运行。</Alert>}
      {save.isSuccess && <Alert severity="success">新策略已生效。</Alert>}
      {status.last_error && <Alert severity="warning">最近调度错误：{status.last_error}</Alert>}
      <Card variant="outlined"><CardContent><Stack spacing={2.5}>
        <FormControlLabel control={<Checkbox checked={policy.enabled} onChange={(event) => setPolicy((current) => ({ ...current, enabled: event.target.checked }))} />} label="启用自动续签" />
        <TextField select label="执行频率" value={mode} onChange={(event) => selectPreset(event.target.value)}><MenuItem value="daily">每天一次（03:00）</MenuItem><MenuItem value="12h">每 12 小时</MenuItem><MenuItem value="6h">每 6 小时</MenuItem><MenuItem value="custom_daily">自定义每天执行时间</MenuItem><MenuItem value="advanced">高级 Cron</MenuItem></TextField>
        {mode === 'custom_daily' && <TextField label="每天执行时间" type="time" value={dailyTime} onChange={(event) => { setDailyTime(event.target.value); setPolicy((current) => ({ ...current, cron_expression: cronForDailyTime(event.target.value) })) }} slotProps={{ inputLabel: { shrink: true } }} />}
        {mode === 'advanced' && <TextField label="Cron 表达式" value={policy.cron_expression} onChange={(event) => setPolicy((current) => ({ ...current, cron_expression: event.target.value }))} helperText="标准五字段：分 时 日 月 周" />}
        <TextField label="时区" value={policy.timezone} onChange={(event) => setPolicy((current) => ({ ...current, timezone: event.target.value }))} helperText="例如 Asia/Shanghai 或 UTC" />
        <TextField label="最大并发数" type="number" value={policy.max_concurrency} onChange={(event) => setPolicy((current) => ({ ...current, max_concurrency: Number(event.target.value) }))} />
        <TextField label="重试次数" type="number" value={policy.retry_count} onChange={(event) => setPolicy((current) => ({ ...current, retry_count: Number(event.target.value) }))} />
        <TextField label="重试间隔（秒）" type="number" value={policy.retry_interval_seconds} onChange={(event) => setPolicy((current) => ({ ...current, retry_interval_seconds: Number(event.target.value) }))} />
      </Stack></CardContent></Card>
      <Alert severity="info">下次运行：{status.next_run_at ? new Date(status.next_run_at).toLocaleString() : '当前未安排'}；最近运行：{status.last_run_at ? new Date(status.last_run_at).toLocaleString() : '尚未运行'}</Alert>
      <Stack direction="row" spacing={2}><Button variant="contained" startIcon={<SaveOutlinedIcon />} disabled={save.isPending} onClick={() => save.mutate()}>保存并立即生效</Button><Button variant="outlined" startIcon={<PlayArrowOutlinedIcon />} disabled={run.isPending} onClick={() => run.mutate()}>立即扫描</Button></Stack>
    </Stack>
  )
}

function presetFor(cron: string): string {
  if (cron === '0 3 * * *') return 'daily'
  if (cron === '0 */12 * * *') return '12h'
  if (cron === '0 */6 * * *') return '6h'
  if (dailyTimeFor(cron)) return 'custom_daily'
  return 'advanced'
}

function dailyTimeFor(cron: string): string | null {
  const match = /^(\d|[1-5]\d) ([01]?\d|2[0-3]) \* \* \*$/.exec(cron)
  if (!match) return null
  return `${match[2].padStart(2, '0')}:${match[1].padStart(2, '0')}`
}

function cronForDailyTime(value: string): string {
  const [hour = '4', minute = '0'] = value.split(':')
  return `${Number(minute)} ${Number(hour)} * * *`
}
