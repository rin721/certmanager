import LockOutlinedIcon from '@mui/icons-material/LockOutlined'
import { zodResolver } from '@hookform/resolvers/zod'
import {
  Alert,
  Avatar,
  Box,
  Button,
  Card,
  CardContent,
  Container,
  Stack,
  TextField,
  Typography,
} from '@mui/material'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { useForm } from 'react-hook-form'
import { useNavigate } from 'react-router-dom'
import { z } from 'zod'
import { ApiError, login } from './api'

const loginSchema = z.object({
  username: z.string().trim().min(1, '请输入用户名'),
  password: z.string().min(1, '请输入密码'),
})

type LoginForm = z.infer<typeof loginSchema>

export function LoginPage({ appName }: { appName: string }) {
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const form = useForm<LoginForm>({
    resolver: zodResolver(loginSchema),
    defaultValues: { username: 'admin', password: '' },
  })
  const mutation = useMutation({
    mutationFn: (value: LoginForm) => login(value.username, value.password),
    onSuccess: async (user) => {
      form.reset({ username: user.username, password: '' })
      queryClient.setQueryData(['current-user'], user)
      await navigate('/', { replace: true })
    },
  })

  const message = mutation.error instanceof ApiError
    ? mutation.error.message
    : mutation.isError ? '登录暂时不可用，请稍后重试。' : undefined

  return (
    <Container maxWidth="xs" sx={{ display: 'grid', minHeight: '100vh', placeItems: 'center', py: 4 }}>
      <Card variant="outlined" sx={{ width: '100%' }}>
        <CardContent sx={{ p: { xs: 3, sm: 4 } }}>
          <Stack component="form" spacing={2.5} onSubmit={form.handleSubmit((value) => mutation.mutate(value))}>
            <Stack spacing={1} sx={{ alignItems: 'center' }}>
              <Avatar sx={{ bgcolor: 'primary.main' }}><LockOutlinedIcon /></Avatar>
              <Typography variant="h5" component="h1">登录 {appName}</Typography>
              <Typography color="text.secondary" variant="body2">使用容器环境变量中配置的管理员账户</Typography>
            </Stack>
            {message && <Alert severity="error">{message}</Alert>}
            <TextField
              label="用户名"
              autoComplete="username"
              autoFocus
              error={Boolean(form.formState.errors.username)}
              helperText={form.formState.errors.username?.message}
              {...form.register('username')}
            />
            <TextField
              label="密码"
              type="password"
              autoComplete="current-password"
              error={Boolean(form.formState.errors.password)}
              helperText={form.formState.errors.password?.message}
              {...form.register('password')}
            />
            <Box>
              <Button type="submit" variant="contained" size="large" fullWidth disabled={mutation.isPending}>
                {mutation.isPending ? '正在登录…' : '登录'}
              </Button>
            </Box>
          </Stack>
        </CardContent>
      </Card>
    </Container>
  )
}
