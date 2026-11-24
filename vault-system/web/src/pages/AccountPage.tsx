import { useState, type FormEvent } from 'react'
import { Alert, Field } from '../components/ui'
import { api, ApiError, getUsername } from '../lib/api'

export default function AccountPage() {
  const [oldPw, setOldPw] = useState('')
  const [newPw, setNewPw] = useState('')
  const [newPw2, setNewPw2] = useState('')
  const [msg, setMsg] = useState<{ tone: 'good' | 'critical'; text: string } | null>(null)
  const [busy, setBusy] = useState(false)
  const mismatch = newPw2.length > 0 && newPw !== newPw2

  async function submit(e: FormEvent) {
    e.preventDefault()
    setBusy(true)
    setMsg(null)
    try {
      await api.changePassword(oldPw, newPw)
      setMsg({ tone: 'good', text: 'Đã đổi mật khẩu.' })
      setOldPw('')
      setNewPw('')
      setNewPw2('')
    } catch (err) {
      setMsg({ tone: 'critical', text: err instanceof ApiError ? err.message : 'Đổi mật khẩu thất bại' })
    } finally {
      setBusy(false)
    }
  }

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Tài khoản</h1>
          <p>Đang đăng nhập: <strong>{getUsername()}</strong></p>
        </div>
      </div>
      <form className="panel" style={{ maxWidth: 460 }} onSubmit={submit}>
        <h2>Đổi mật khẩu</h2>
        {msg && <Alert tone={msg.tone}>{msg.text}</Alert>}
        <div className="grid" style={{ gap: 14 }}>
          <Field label="Mật khẩu hiện tại">
            <input className="input" type="password" autoComplete="current-password" value={oldPw} onChange={(e) => setOldPw(e.target.value)} />
          </Field>
          <Field label="Mật khẩu mới" hint="Ít nhất 8 ký tự">
            <input className="input" type="password" autoComplete="new-password" value={newPw} onChange={(e) => setNewPw(e.target.value)} />
          </Field>
          <Field label="Nhập lại mật khẩu mới" error={mismatch ? 'Không khớp' : null}>
            <input className="input" type="password" autoComplete="new-password" value={newPw2} onChange={(e) => setNewPw2(e.target.value)} />
          </Field>
          <div>
            <button className="btn btn-primary" disabled={busy || !oldPw || newPw.length < 8 || newPw !== newPw2}>Đổi mật khẩu</button>
          </div>
        </div>
      </form>
    </>
  )
}
