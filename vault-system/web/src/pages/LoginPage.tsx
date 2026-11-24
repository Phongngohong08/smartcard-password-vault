import { useState, type FormEvent } from 'react'
import { useNavigate } from 'react-router-dom'
import { IconCard } from '../components/Icons'
import { Alert, Field } from '../components/ui'
import { api, ApiError, saveSession } from '../lib/api'

export default function LoginPage({ onLogin }: { onLogin: (user: string) => void }) {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const navigate = useNavigate()

  async function submit(e: FormEvent) {
    e.preventDefault()
    setBusy(true)
    setError(null)
    try {
      const r = await api.login(username.trim(), password)
      saveSession(r.token, r.username)
      onLogin(r.username)
      navigate('/', { replace: true })
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Đăng nhập thất bại')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="login-page">
      <form className="panel login-card" onSubmit={submit}>
        <div className="brand">
          <span style={{ color: 'var(--accent)', display: 'inline-flex' }}><IconCard size={30} /></span>
          <div>Vault Admin<small>Quản trị thẻ quản lý mật khẩu</small></div>
        </div>
        {error && <Alert tone="critical">{error}</Alert>}
        <div className="grid" style={{ gap: 14 }}>
          <Field label="Tên đăng nhập">
            <input className="input" autoFocus autoComplete="username" value={username} onChange={(e) => setUsername(e.target.value)} />
          </Field>
          <Field label="Mật khẩu">
            <input className="input" type="password" autoComplete="current-password" value={password}
              onChange={(e) => setPassword(e.target.value)} />
          </Field>
          <button className="btn btn-primary" disabled={busy || !username || !password}>
            {busy ? 'Đang đăng nhập...' : 'Đăng nhập'}
          </button>
        </div>
        <p className="muted" style={{ fontSize: 12.5, marginTop: 14, marginBottom: 0 }}>
          Người dùng không có tài khoản ở đây - họ đăng nhập bằng thẻ trên ứng dụng.
        </p>
      </form>
    </div>
  )
}
