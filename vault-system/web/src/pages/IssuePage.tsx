import { useEffect, useRef, useState, type FormEvent } from 'react'
import { Link } from 'react-router-dom'
import { IconCard, IconCheck, IconRefresh, IconSpinner, IconX } from '../components/Icons'
import { Alert, Field } from '../components/ui'
import { agent, AgentError, useAgent } from '../lib/agent'
import { api, ApiError, type Card } from '../lib/api'
import { CARD_STATE_LABEL, fmtBytes, utf8Len } from '../lib/format'

type StepState = 'wait' | 'run' | 'done' | 'fail'

const STEPS = [
  'Kiểm tra thẻ trắng trong đầu đọc',
  'Ghi thẻ: ISSUE, hồ sơ, ảnh - thẻ tự sinh Master Key và cặp khoá RSA-2048',
  'Lưu khoá công khai vào CSDL (chờ kích hoạt)',
  'Server gửi challenge, thẻ ký bằng khoá riêng',
  'Server kiểm tra chữ ký bằng khoá công khai và kích hoạt thẻ',
]

interface Avatar {
  dataUrl: string
  base64: string
  size: number
}

interface Form {
  cardId: string
  ownerName: string
  dob: string
  email: string
  phone: string
  pin: string
  pin2: string
  puk: string
  replaces: string
}

const EMPTY: Form = { cardId: '', ownerName: '', dob: '', email: '', phone: '', pin: '', pin2: '', puk: '', replaces: '' }

function validate(f: Form): Partial<Record<keyof Form, string>> {
  const e: Partial<Record<keyof Form, string>> = {}
  if (!/^[A-Z0-9]{8}$/.test(f.cardId)) e.cardId = 'Đúng 8 ký tự chữ hoa hoặc số, ví dụ SC000001'
  if (!f.ownerName.trim()) e.ownerName = 'Bắt buộc'
  else if (utf8Len(f.ownerName.trim()) > 64) e.ownerName = 'Tối đa 64 byte (khoảng 30 ký tự có dấu)'
  if (f.email && (utf8Len(f.email) > 64 || !/^[^@\s]+@[^@\s]+$/.test(f.email))) e.email = 'Email không hợp lệ (tối đa 64 byte)'
  if (f.phone && !/^[0-9+ ]{1,16}$/.test(f.phone)) e.phone = 'Chỉ chữ số, tối đa 16 ký tự'
  if (!/^[\x20-\x7E]{6,12}$/.test(f.pin)) e.pin = '6-12 ký tự (chữ, số, ký hiệu không dấu)'
  if (f.pin2 !== f.pin) e.pin2 = 'Không khớp với PIN'
  if (!/^[0-9]{8}$/.test(f.puk)) e.puk = 'Đúng 8 chữ số'
  return e
}

/** PUK 8 chữ số ngẫu nhiên, không thiên lệch (bỏ byte ≥ 250). */
function randomPuk(): string {
  let s = ''
  const buf = new Uint8Array(32)
  while (s.length < 8) {
    crypto.getRandomValues(buf)
    for (const b of buf) if (b < 250 && s.length < 8) s += String(b % 10)
  }
  return s
}

/** Cắt ảnh vuông, thu về 64x64 JPEG ≤ 3 072 byte (16 khối x 192 byte trên thẻ). */
async function makeAvatar(file: File): Promise<Avatar> {
  const img = await createImageBitmap(file)
  const canvas = document.createElement('canvas')
  canvas.width = canvas.height = 64
  const ctx = canvas.getContext('2d')!
  const s = Math.min(img.width, img.height)
  ctx.drawImage(img, (img.width - s) / 2, (img.height - s) / 2, s, s, 0, 0, 64, 64)
  for (let q = 0.85; q >= 0.25; q -= 0.1) {
    const dataUrl = canvas.toDataURL('image/jpeg', q)
    const base64 = dataUrl.slice(dataUrl.indexOf(',') + 1)
    const size = Math.floor((base64.length * 3) / 4) - (base64.endsWith('==') ? 2 : base64.endsWith('=') ? 1 : 0)
    if (size <= 3072) return { dataUrl, base64, size }
  }
  throw new Error('Ảnh quá chi tiết, không nén được xuống 3 KB')
}

function errMsg(e: unknown): string {
  if (e instanceof ApiError || e instanceof AgentError || e instanceof Error) return e.message
  return 'Lỗi không xác định'
}

export default function IssuePage() {
  const agentCtx = useAgent()
  const [form, setForm] = useState<Form>(EMPTY)
  const [touched, setTouched] = useState(false)
  const [avatar, setAvatar] = useState<Avatar | null>(null)
  const [avatarErr, setAvatarErr] = useState<string | null>(null)
  const [oldCards, setOldCards] = useState<Card[]>([])
  const [steps, setSteps] = useState<StepState[]>(STEPS.map(() => 'wait'))
  const [stepNotes, setStepNotes] = useState<string[]>(STEPS.map(() => ''))
  const [running, setRunning] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [failedAt, setFailedAt] = useState<number | null>(null)
  const [done, setDone] = useState<Card | null>(null)
  const [blankBusy, setBlankBusy] = useState(false)
  const issueResult = useRef<{ modulusHex: string; exponentHex: string } | null>(null)
  const current = useRef(0)

  async function loadNextId() {
    try {
      const r = await api.nextCardId()
      setForm((f) => ({ ...f, cardId: r.cardId }))
    } catch {
      // để admin tự nhập
    }
  }

  useEffect(() => {
    void loadNextId()
    api.cards().then((cs) => setOldCards(cs.filter((c) => c.status === 'REVOKED' || c.status === 'LOCKED'))).catch(() => {})
  }, [])

  const errors = validate(form)
  const valid = Object.keys(errors).length === 0
  const set = (k: keyof Form) => (e: { target: { value: string } }) =>
    setForm((f) => ({ ...f, [k]: k === 'cardId' ? e.target.value.toUpperCase() : e.target.value }))
  const err = (k: keyof Form) => (touched ? errors[k] : undefined)

  function mark(i: number, s: StepState, note?: string) {
    current.current = i
    setSteps((prev) => prev.map((x, j) => (j === i ? s : x)))
    if (note !== undefined) setStepNotes((prev) => prev.map((x, j) => (j === i ? note : x)))
  }

  async function run(from: number) {
    setRunning(true)
    setError(null)
    setFailedAt(null)
    agentCtx.setBusy(true)
    setSteps((prev) => prev.map((x, j) => (j >= from ? 'wait' : x)))
    const cardId = form.cardId
    try {
      if (from <= 0) {
        mark(0, 'run')
        const c = await agent.card()
        if (!c.present) throw new Error(c.error ?? 'Chưa có thẻ trong đầu đọc')
        if (c.stateName !== 'UNISSUED') {
          throw new Error(`Thẻ đang cắm không phải thẻ trắng (${CARD_STATE_LABEL[c.stateName ?? ''] ?? c.stateName}, mã ${c.cardId}).`)
        }
        mark(0, 'done', 'Thẻ trắng, applet Vault sẵn sàng')
      }
      if (from <= 1) {
        mark(1, 'run')
        const r = await agent.issue({
          cardId, pin: form.pin, puk: form.puk,
          profile: { name: form.ownerName.trim(), dob: form.dob, email: form.email.trim(), phone: form.phone.trim() },
          avatarBase64: avatar?.base64,
        })
        issueResult.current = r
        mark(1, 'done', r.steps.join(' · '))
      }
      if (from <= 2) {
        mark(2, 'run')
        const k = issueResult.current!
        await api.registerCard({
          cardId, ownerName: form.ownerName.trim(), ownerEmail: form.email.trim(), ownerPhone: form.phone.trim(),
          modulusHex: k.modulusHex, exponentHex: k.exponentHex, replacesCardId: form.replaces || undefined,
        })
        mark(2, 'done', 'Trạng thái trong CSDL: chờ kích hoạt')
      }
      mark(3, 'run')
      const ch = await api.challenge(cardId)
      const sg = await agent.sign(ch.challenge)
      if (sg.cardId !== cardId) throw new Error(`Thẻ đang cắm là ${sg.cardId}, không phải ${cardId}`)
      mark(3, 'done', `Challenge 32 byte ${ch.challenge.slice(0, 16)}… → chữ ký 256 byte`)
      mark(4, 'run')
      const card = await api.activate(cardId, ch.challenge, sg.signature)
      mark(4, 'done', `Chữ ký hợp lệ · khoá ${card.keyFingerprint}`)
      setDone(card)
    } catch (e) {
      mark(current.current, 'fail')
      setFailedAt(current.current)
      setError(errMsg(e))
    } finally {
      setRunning(false)
      agentCtx.setBusy(false)
      void agentCtx.refresh()
    }
  }

  function submit(e: FormEvent) {
    e.preventDefault()
    setTouched(true)
    if (valid) void run(0)
  }

  async function blankCard() {
    setBlankBusy(true)
    try {
      await agent.blankCard()
      await agentCtx.refresh()
    } catch (e) {
      setError(errMsg(e))
    } finally {
      setBlankBusy(false)
    }
  }

  async function onAvatar(file: File | undefined) {
    setAvatarErr(null)
    setAvatar(null)
    if (!file) return
    try {
      setAvatar(await makeAvatar(file))
    } catch (e) {
      setAvatarErr(errMsg(e))
    }
  }

  function reset() {
    setForm(EMPTY)
    setTouched(false)
    setAvatar(null)
    setDone(null)
    setError(null)
    setFailedAt(null)
    setSteps(STEPS.map(() => 'wait'))
    setStepNotes(STEPS.map(() => ''))
    issueResult.current = null
    void loadNextId()
  }

  const started = steps.some((s) => s !== 'wait')
  const c = agentCtx.card

  if (done) {
    return (
      <>
        <div className="page-head"><div><h1>Phát hành thẻ</h1></div></div>
        <section className="panel">
          <Alert tone="good">
            Đã phát hành và kích hoạt thẻ <strong className="mono">{done.cardId}</strong> cho <strong>{done.ownerName}</strong>.
          </Alert>
          <h3>Mã PUK của thẻ</h3>
          <div className="secret-box">{form.puk}</div>
          <p className="ink-2" style={{ marginTop: 10 }}>
            Giao PUK cho chủ thẻ ngay bây giờ (in hoặc chép tay). Hệ thống <strong>không lưu PUK</strong> - chỉ thẻ biết nó.
            Mất PUK mà khoá PIN thì phải thu hồi thẻ.
          </p>
          <StepList steps={steps} notes={stepNotes} />
          <div className="btn-row" style={{ marginTop: 16 }}>
            <Link className="btn btn-primary" to={`/cards/${done.cardId}`}>Xem thẻ</Link>
            <button className="btn" onClick={reset}>Phát hành thẻ khác</button>
          </div>
        </section>
      </>
    )
  }

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Phát hành thẻ</h1>
          <p>Ghi thông tin chủ thẻ vào một thẻ trắng. PIN và PUK chỉ nằm trên thẻ, không lưu ở server.</p>
        </div>
      </div>

      <div className="grid grid-3" style={{ alignItems: 'start' }}>
        <form className="panel" onSubmit={submit} noValidate>
          <h2>Thông tin thẻ</h2>
          <div className="form-grid">
            <Field label="Mã thẻ" error={err('cardId')} hint="8 ký tự, server gợi ý mã tiếp theo">
              <input className="input mono" value={form.cardId} onChange={set('cardId')} maxLength={8} aria-invalid={!!err('cardId')} />
            </Field>
            <Field label="Thay cho thẻ cũ (nếu có)" hint="Thẻ mới được khôi phục bản sao lưu của thẻ cũ">
              <select className="input" value={form.replaces} onChange={set('replaces')}>
                <option value="">Không</option>
                {oldCards.map((oc) => <option key={oc.cardId} value={oc.cardId}>{oc.cardId} - {oc.ownerName}</option>)}
              </select>
            </Field>
            <Field label="Họ tên chủ thẻ" error={err('ownerName')} className="span-2">
              <input className="input" value={form.ownerName} onChange={set('ownerName')} aria-invalid={!!err('ownerName')} />
            </Field>
            <Field label="Ngày sinh">
              <input className="input" type="date" value={form.dob} onChange={set('dob')} />
            </Field>
            <Field label="Số điện thoại" error={err('phone')}>
              <input className="input" value={form.phone} onChange={set('phone')} inputMode="tel" aria-invalid={!!err('phone')} />
            </Field>
            <Field label="Email" error={err('email')} className="span-2">
              <input className="input" type="email" value={form.email} onChange={set('email')} aria-invalid={!!err('email')} />
            </Field>
            <Field label="PIN ban đầu" error={err('pin')} hint="6-12 ký tự">
              <input className="input" type="password" autoComplete="new-password" value={form.pin} onChange={set('pin')} aria-invalid={!!err('pin')} />
            </Field>
            <Field label="Nhập lại PIN" error={err('pin2')}>
              <input className="input" type="password" autoComplete="new-password" value={form.pin2} onChange={set('pin2')} aria-invalid={!!err('pin2')} />
            </Field>
            <Field label="PUK" error={err('puk')} hint="8 chữ số, dùng để mở khoá khi nhập sai PIN 3 lần">
              <div className="input-group">
                <input className="input mono" value={form.puk} onChange={set('puk')} maxLength={8} inputMode="numeric" aria-invalid={!!err('puk')} />
                <button type="button" className="btn" onClick={() => setForm((f) => ({ ...f, puk: randomPuk() }))}>Sinh ngẫu nhiên</button>
              </div>
            </Field>
            <Field label="Ảnh đại diện (tuỳ chọn)" error={avatarErr} hint={avatar ? `64×64 JPEG, ${fmtBytes(avatar.size)} - tối đa 3 KB` : 'Ảnh được thu về 64×64, tối đa 3 KB'}>
              <div className="input-group" style={{ alignItems: 'center' }}>
                {avatar && <img className="avatar-preview" src={avatar.dataUrl} alt="Ảnh đại diện" />}
                <input type="file" accept="image/*" onChange={(e) => onAvatar(e.target.files?.[0])} />
              </div>
            </Field>
          </div>
          <div className="btn-row" style={{ marginTop: 18 }}>
            <button className="btn btn-primary" disabled={running || (touched && !valid)}>
              {running ? <><IconSpinner size={16} /> Đang phát hành...</> : 'Phát hành thẻ'}
            </button>
            {failedAt !== null && failedAt >= 2 && !running && (
              <button type="button" className="btn" onClick={() => run(failedAt)}>
                <IconRefresh size={16} /> Thử lại từ bước {failedAt + 1}
              </button>
            )}
          </div>
        </form>

        <div className="grid" style={{ gap: 16 }}>
          <section className="panel">
            <h2>Đầu đọc thẻ</h2>
            <div className="reader-box">
              <div className="card-icon"><IconCard size={24} /></div>
              <div style={{ minWidth: 0 }}>
                {agentCtx.online === false && <><strong>Card Agent chưa chạy</strong><div className="muted">Chạy scripts\agent.ps1 trên máy này</div></>}
                {agentCtx.online && !c?.present && <><strong>Chưa có thẻ</strong><div className="muted">{c?.error}</div></>}
                {agentCtx.online && c?.present && (
                  <>
                    <strong>{c.cardId ? `Thẻ ${c.cardId}` : 'Thẻ trắng'}</strong>
                    <div className={c.stateName === 'UNISSUED' ? 'ink-2' : 'muted'}>
                      {c.stateName === 'UNISSUED' ? 'Sẵn sàng phát hành' : `${CARD_STATE_LABEL[c.stateName ?? ''] ?? c.stateName} - không phải thẻ trắng`}
                    </div>
                  </>
                )}
              </div>
            </div>
            {agentCtx.health?.dev && (
              <div style={{ marginTop: 12 }}>
                <button className="btn btn-sm" onClick={blankCard} disabled={blankBusy || running}>
                  {blankBusy ? <IconSpinner size={14} /> : null} Nạp thẻ trắng (simulator)
                </button>
                <div className="muted" style={{ fontSize: 12, marginTop: 6 }}>
                  Chế độ dev: nạp lại applet = cắm một thẻ trắng mới. Thẻ đang cắm sẽ bị xoá.
                </div>
              </div>
            )}
          </section>

          {started && (
            <section className="panel">
              <h2>Tiến trình</h2>
              {error && <Alert tone="critical">{error}</Alert>}
              <StepList steps={steps} notes={stepNotes} />
            </section>
          )}
        </div>
      </div>
    </>
  )
}

function StepList({ steps, notes }: { steps: StepState[]; notes: string[] }) {
  return (
    <ol className="steps">
      {STEPS.map((title, i) => (
        <li key={i} className={`step-${steps[i]}`}>
          <span className="step-icon">
            {steps[i] === 'done' ? <IconCheck size={14} /> : steps[i] === 'fail' ? <IconX size={14} /> : steps[i] === 'run' ? <IconSpinner size={14} /> : i + 1}
          </span>
          <div>
            <div>{title}</div>
            {notes[i] && <div className="step-sub">{notes[i]}</div>}
          </div>
        </li>
      ))}
    </ol>
  )
}
