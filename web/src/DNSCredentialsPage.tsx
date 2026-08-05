import AddOutlinedIcon from '@mui/icons-material/AddOutlined'
import DeleteOutlineIcon from '@mui/icons-material/DeleteOutlined'
import EditOutlinedIcon from '@mui/icons-material/EditOutlined'
import {
  Alert,
  Button,
  Chip,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
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
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useMemo, useState } from 'react'
import {
  createDNSCredential,
  deleteDNSCredential,
  listDNSCredentialReferences,
  listDNSCredentials,
  listDNSProviders,
  renameDNSCredential,
  testDNSCredential,
  updateDNSCredential,
  type DNSCredential,
} from './api'

export function DNSCredentialsPage() {
  const client = useQueryClient()
  const providers = useQuery({ queryKey: ['dns-providers'], queryFn: listDNSProviders })
  const credentials = useQuery({ queryKey: ['dns-credentials'], queryFn: listDNSCredentials })
  const [open, setOpen] = useState(false)
  const [editing, setEditing] = useState<DNSCredential | null>(null)
  const [referencesFor, setReferencesFor] = useState<DNSCredential | null>(null)
  const [renaming, setRenaming] = useState<DNSCredential | null>(null)
  const [renamedName, setRenamedName] = useState('')
  const [name, setName] = useState('')
  const [providerCode, setProviderCode] = useState('cloudflare')
  const [sourceMode, setSourceMode] = useState<'encrypted' | 'environment'>('encrypted')
  const [customCode, setCustomCode] = useState('dns_')
  const [values, setValues] = useState<Record<string, string>>({})
  const selectedProvider = useMemo(() => providers.data?.find((item) => item.provider_code === providerCode), [providerCode, providers.data])
  const saveMutation = useMutation({
    mutationFn: () => {
      const input = {
      name, provider: providerCode, custom_acme_code: selectedProvider?.custom ? customCode : undefined,
      source_mode: sourceMode,
      values: sourceMode === 'encrypted' ? values : undefined,
      environment_refs: sourceMode === 'environment' ? values : undefined,
      } as const
      return editing ? updateDNSCredential(editing.id, input) : createDNSCredential(input)
    },
    onSuccess: async () => {
      setOpen(false); setEditing(null); setName(''); setValues({}); setCustomCode('dns_')
      await client.invalidateQueries({ queryKey: ['dns-credentials'] })
    },
  })
  const removeMutation = useMutation({
    mutationFn: deleteDNSCredential,
    onSuccess: () => client.invalidateQueries({ queryKey: ['dns-credentials'] }),
  })
  const testMutation = useMutation({ mutationFn: testDNSCredential })
  const renameMutation = useMutation({
    mutationFn: () => renameDNSCredential(renaming!.id, renamedName),
    onSuccess: async () => { setRenaming(null); setRenamedName(''); await client.invalidateQueries({ queryKey: ['dns-credentials'] }) },
  })
  const references = useQuery({
    queryKey: ['dns-credential-references', referencesFor?.id],
    queryFn: () => listDNSCredentialReferences(referencesFor!.id),
    enabled: Boolean(referencesFor),
  })
  const startEdit = (item: DNSCredential) => {
    setEditing(item); setName(item.name); setProviderCode(item.provider); setSourceMode(item.source_mode)
    setCustomCode(item.acme_dns_code); setValues(item.source_mode === 'environment' ? (item.environment_refs ?? {}) : {}); setOpen(true)
  }
  return (
    <Stack spacing={3}>
      <Stack direction={{ xs: 'column', sm: 'row' }} sx={{ justifyContent: 'space-between', gap: 2 }}><div><Typography variant="h4">DNS 凭据</Typography><Typography color="text.secondary">Token 仅以密文保存；列表永不返回完整敏感值</Typography></div><Button variant="contained" startIcon={<AddOutlinedIcon />} onClick={() => setOpen(true)}>新建凭据</Button></Stack>
      <Alert severity="info">“本地校验”只检查凭据解密或环境变量引用，不会向第三方 DNS Provider 发起在线请求，也不能验证 Token 权限或 Zone 资源范围。</Alert>
      {(credentials.isError || providers.isError) && <Alert severity="error">读取 DNS Provider 配置失败。</Alert>}
      {testMutation.isSuccess && <Alert severity="success">凭据已成功解密或解析环境变量引用；未验证第三方 API 权限。</Alert>}
      {testMutation.isError && <Alert severity="error">凭据本地校验失败，请检查密文或容器环境变量。</Alert>}
      <TableContainer component={Paper} variant="outlined"><Table sx={{ minWidth: 760 }}><TableHead><TableRow><TableCell>名称</TableCell><TableCell>Provider</TableCell><TableCell>来源</TableCell><TableCell>字段</TableCell><TableCell align="right">操作</TableCell></TableRow></TableHead><TableBody>{credentials.data?.map((item) => <TableRow key={item.id}><TableCell>{item.name}</TableCell><TableCell>{item.acme_dns_code}</TableCell><TableCell>{item.source_mode === 'encrypted' ? '数据库加密' : '环境变量引用'}</TableCell><TableCell>{item.masked_fields.map((field) => <Chip key={field} label={`${field}=••••••`} size="small" sx={{ mr: 0.5 }} />)}</TableCell><TableCell align="right"><Button disabled={testMutation.isPending} onClick={() => testMutation.mutate(item.id)}>本地校验</Button><Button onClick={() => setReferencesFor(item)}>引用</Button><Button onClick={() => { setRenaming(item); setRenamedName(item.name) }}>改名</Button><Button startIcon={<EditOutlinedIcon />} onClick={() => startEdit(item)}>替换密钥</Button><Button color="error" startIcon={<DeleteOutlineIcon />} disabled={removeMutation.isPending} onClick={() => removeMutation.mutate(item.id)}>删除</Button></TableCell></TableRow>)}</TableBody></Table></TableContainer>
      <Dialog open={open} onClose={() => { setOpen(false); setEditing(null); setValues({}) }} maxWidth="sm" fullWidth><DialogTitle>{editing ? '替换 DNS 凭据' : '新建 DNS 凭据'}</DialogTitle><DialogContent><Stack spacing={2.5} sx={{ pt: 1 }}>
        <Alert severity="info">保存后仅显示字段掩码，无法重新取回完整 Token。替换操作会保持凭据 ID，因此已有证书引用不会失效。</Alert>
        {saveMutation.isError && <Alert severity="error">凭据配置无效，请检查必填字段和变量名。</Alert>}
        <TextField label="名称" value={name} onChange={(event) => setName(event.target.value)} />
        <TextField select label="Provider" value={providerCode} onChange={(event) => { setProviderCode(event.target.value); setValues({}) }}>{providers.data?.map((provider) => <MenuItem key={provider.provider_code} value={provider.provider_code}>{provider.display_name}</MenuItem>)}</TextField>
        {selectedProvider?.documentation_hint && <Alert severity="warning">{selectedProvider.documentation_hint}</Alert>}
        <TextField select label="凭据来源" value={sourceMode} onChange={(event) => { setSourceMode(event.target.value as 'encrypted' | 'environment'); setValues({}) }}><MenuItem value="encrypted">加密保存到 SQLite</MenuItem><MenuItem value="environment">引用容器环境变量</MenuItem></TextField>
        {selectedProvider?.custom && <TextField label="acme.sh DNS Provider Code" value={customCode} onChange={(event) => setCustomCode(event.target.value)} helperText="格式：dns_provider" />}
        {selectedProvider?.custom ? <TextField label={sourceMode === 'encrypted' ? '环境变量键值对' : '子进程变量与来源变量映射'} multiline minRows={4} value={Object.entries(values).map(([key, value]) => `${key}=${value}`).join('\n')} onChange={(event) => setValues(parsePairs(event.target.value))} helperText={sourceMode === 'encrypted' ? '每行 KEY=value，键必须全大写' : '每行 CHILD_KEY=CONTAINER_ENV_NAME，两个键都必须全大写'} /> : selectedProvider?.fields.map((field) => <TextField key={field.name} label={field.label} type={sourceMode === 'encrypted' && field.secret ? 'password' : 'text'} required={field.required} value={values[field.name] ?? ''} onChange={(event) => setValues((current) => ({ ...current, [field.name]: event.target.value }))} helperText={sourceMode === 'environment' ? `填写包含 ${field.name} 值的容器环境变量名称` : field.description} autoComplete="off" />)}
      </Stack></DialogContent><DialogActions><Button onClick={() => { setOpen(false); setEditing(null); setValues({}) }}>取消</Button><Button variant="contained" disabled={!name || saveMutation.isPending} onClick={() => saveMutation.mutate()}>保存</Button></DialogActions></Dialog>
      <Dialog open={Boolean(referencesFor)} onClose={() => setReferencesFor(null)} fullWidth maxWidth="sm"><DialogTitle>引用 {referencesFor?.name} 的证书</DialogTitle><DialogContent>{references.isLoading ? <Typography>加载中…</Typography> : references.data?.length ? <Stack spacing={1}>{references.data.map((item) => <Paper variant="outlined" sx={{ p: 1.5 }} key={item.id}><Typography sx={{ fontWeight: 600 }}>{item.name}</Typography><Typography color="text.secondary">{item.primary_domain} · {item.status}</Typography></Paper>)}</Stack> : <Alert severity="info">当前没有证书引用此凭据。</Alert>}</DialogContent><DialogActions><Button onClick={() => setReferencesFor(null)}>关闭</Button></DialogActions></Dialog>
      <Dialog open={Boolean(renaming)} onClose={() => { setRenaming(null); setRenamedName('') }} fullWidth maxWidth="xs"><DialogTitle>编辑凭据名称</DialogTitle><DialogContent><TextField autoFocus fullWidth label="名称" value={renamedName} onChange={(event) => setRenamedName(event.target.value)} sx={{ mt: 1 }} />{renameMutation.isError && <Alert severity="error" sx={{ mt: 2 }}>名称无效或保存失败。</Alert>}</DialogContent><DialogActions><Button onClick={() => { setRenaming(null); setRenamedName('') }}>取消</Button><Button variant="contained" disabled={!renamedName.trim() || renameMutation.isPending} onClick={() => renameMutation.mutate()}>保存</Button></DialogActions></Dialog>
    </Stack>
  )
}

function parsePairs(value: string): Record<string, string> {
  const result: Record<string, string> = {}
  for (const line of value.split('\n')) {
    const index = line.indexOf('=')
    if (index > 0) result[line.slice(0, index).trim()] = line.slice(index + 1).trim()
  }
  return result
}
