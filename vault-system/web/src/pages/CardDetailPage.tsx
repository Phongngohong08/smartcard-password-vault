import { useCallback, useEffect, useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { IconBan, IconLock, IconShield, IconSpinner, IconUnlock } from '../components/Icons'
import LogTable from '../components/LogTable'
import { Alert, CardStateBadge, Field, Modal, PendingBadge, StatusBadge } from '../components/ui'
import { agent, AgentError, isInserted, useAgent } from '../lib/agent'
import { api, ApiError, type CardDetail } from '../lib/api'
import { fmtBytes, fmtDateTime, fmtRelative, PENDING_LABEL } from '../lib/format'

type Kind = 'lock' | 'unlock' | 'revoke'
const KIND_LABEL: Record<Kind, string> = { lock: 'Khoá thẻ', unlock: 'Mở khoá thẻ', revoke: 'Thu hồi thẻ' }

function errMsg(e: unknown): string {
  return e instanceof ApiError || e instanceof AgentError || e instanceof Error ? e.message : 'Lỗi không xác định'
}

export default function CardDetailPage() {
  const id = (useParams().id ?? '').toUpperCase()
  const navigate = useNavigate()
  const agentCtx = useAgent()
  const inserted = isInserted(agentCtx.card, id)
  const [d, setD] = useState<CardDetail | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [notice, setNotice] = useState<{ tone: 'good' | 'warning' | 'critical'; text: string } | null>(null)
  const [busy, setBusy] = useState(false)
  const [confirm, setConfirm] = useState<Kind | null>(null)

  const load = useCallback(async () => {
    try {
      setD(await api.card(id))
      setError(null)
    } catch (e) {
      setError(errMsg(e))
    }
  }, [id])

  useEffect(() => {
    void load()
  }, [load])

  async function withBusy(fn: () => Promise<void>) {
    setBusy(true)
    setNotice(null)
    agentCtx.setBusy(true)
    try {
      await fn()
    } catch (e) {
      setNotice({ tone: 'critical', text: errMsg(e) })
    } finally {
      setBusy(false)
      agentCtx.setBusy(false)
      void agentCtx.refresh()
      void load()
    }
  }

  // Khoá / mở khoá / thu hồi: thẻ đang cắm thì làm trên thẻ trước, rồi mới cập nhật CSDL.
  const doAction = (kind: Kind, reason: string) =>
    withBusy(async () => {
      setConfirm(null)
      if (inserted) await agent.admin(id, kind.toUpperCase() as 'LOCK' | 'UNLOCK' | 'REVOKE')
      const card = await api.cardAction(id, kind, inserted, reason || undefined)
      setNotice(inserted
        ? { tone: 'good', text: `${KIND_LABEL[kind]}: đã thực hiện trên thẻ và cập nhật CSDL.` }
        : { tone: 'warning', text: `${KIND_LABEL[kind]}: đã cập nhật CSDL. ${PENDING_LABEL[card.pendingAction] || 'Không cần đồng bộ'} - sẽ thực hiện khi thẻ kết nối lần sau.` })
    })

  // Kiểm tra thẻ thật / giả: server sinh challenge, thẻ ký, server kiểm bằng khoá công khai đã lưu.
  const checkRsa = () =>
    withBusy(async () => {
      const ch = await api.challenge(id)
      const sg = await agent.sign(ch.challenge)
      try {
        await api.verify(id, ch.challenge, sg.signature)
        setNotice({ tone: 'good', text: 'Thẻ thật: chữ ký khớp khoá công khai trong CSDL.' })
      } catch (e) {
        if (e instanceof ApiError && e.code === 'BAD_SIGNATURE') {
          setNotice({ tone: 'critical', text: 'THẺ GIẢ: chữ ký không khớp khoá công khai đã lưu cho mã thẻ này.' })
        } else if (e instanceof ApiError && (e.code === 'CARD_LOCKED' || e.code === 'CARD_REVOKED')) {
          setNotice({ tone: 'warning', text: `Chữ ký hợp lệ (thẻ thật), nhưng ${e.message.toLowerCase()}.` })
        } else throw e
      }
    })

  const activate = () =>
    withBusy(async () => {
      const ch = await api.challenge(id)
      const sg = await agent.sign(ch.challenge)
      await api.activate(id, ch.challenge, sg.signature)
      setNotice({ tone: 'good', text: 'Đã kích hoạt thẻ.' })
    })

  const removePending = () =>
    withBusy(async () => {
      await api.deletePending(id)
      navigate('/cards')
    })

  if (error) return <Alert tone="critical">{error}</Alert>
  if (!d) return <div className="muted">Đang tải...</div>
  const c = d.card

  return (
    <>
      <div className="page-head">
        <div>
          <div className="muted" style={{ fontSize: 13 }}><Link to="/cards">Thẻ</Link> / {c.cardId}</div>
          <h1 style={{ display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap' }}>
            <span className="mono" style={{ fontSize: 22 }}>{c.cardId}</span> {c.ownerName}
          </h1>
          <div className="btn-row" style={{ marginTop: 8 }}>
            <StatusBadge status={c.status} />
            <PendingBadge action={c.pendingAction} />
          </div>
        </div>
      </div>

      {notice && <Alert tone={notice.tone}>{notice.text}</Alert>}

      <div className="grid grid-2" style={{ alignItems: 'start' }}>
        <section className="panel">
          <h2>Thông tin</h2>
          <dl className="kv">
            <dt>Chủ thẻ</dt><dd>{c.ownerName}</dd>
            <dt>Email</dt><dd>{c.ownerEmail ?? '—'}</dd>
            <dt>Số điện thoại</dt><dd>{c.ownerPhone ?? '—'}</dd>
            <dt>Ngày cấp</dt><dd>{fmtDateTime(c.issuedAt)}{c.issuedBy && <span className="muted"> · bởi {c.issuedBy}</span>}</dd>
            <dt>Lần cuối thấy</dt><dd>{fmtRelative(c.lastSeenAt)}</dd>
            {c.revokedAt && <><dt>Thu hồi lúc</dt><dd>{fmtDateTime(c.revokedAt)}</dd></>}
            {c.replacesCardId && <><dt>Thay cho thẻ</dt><dd><Link to={`/cards/${c.replacesCardId}`} className="mono">{c.replacesCardId}</Link></dd></>}
            {d.replacedBy && <><dt>Đã thay bằng</dt><dd><Link to={`/cards/${d.replacedBy}`} className="mono">{d.replacedBy}</Link></dd></>}
            <dt>Khoá công khai</dt>
            <dd>
              <span className="mono">RSA-2048 · {c.keyFingerprint}</span>
              <details><summary className="muted" style={{ cursor: 'pointer', fontSize: 12.5 }}>Xem modulus</summary>
                <code style={{ wordBreak: 'break-all', fontSize: 11 }}>{d.modulusHex}</code>
                <div className="muted" style={{ fontSize: 12 }}>Số mũ: {parseInt(d.exponentHex, 16)}</div>
              </details>
            </dd>
          </dl>
        </section>

        <section className="panel">
          <h2>Trạng thái và quản trị</h2>
          <dl className="kv" style={{ marginBottom: 14 }}>
            <dt>Trong CSDL</dt><dd><StatusBadge status={c.status} /></dd>
            <dt>Trên thẻ (lần cuối)</dt><dd><CardStateBadge state={c.cardState} /></dd>
            <dt>Đầu đọc</dt>
            <dd>{inserted ? <strong>Thẻ này đang cắm</strong> : <span className="muted">Thẻ không cắm</span>}</dd>
          </dl>
          {c.status !== 'PENDING' && c.status !== 'REVOKED' && (
            <Alert tone="info">
              {inserted
                ? 'Thẻ đang cắm: thao tác được ghi lên thẻ (xác thực admin bằng challenge-response) rồi cập nhật CSDL.'
                : 'Thẻ không cắm: chỉ cập nhật CSDL, thẻ bị từ chối ngay ở lần kết nối sau và thao tác được ghi lên thẻ khi đó.'}
            </Alert>
          )}
          <div className="btn-row">
            {c.status === 'ACTIVE' && (
              <button className="btn" disabled={busy} onClick={() => setConfirm('lock')}><IconLock size={16} /> Khoá thẻ</button>
            )}
            {c.status === 'LOCKED' && (
              <button className="btn" disabled={busy} onClick={() => setConfirm('unlock')}><IconUnlock size={16} /> Mở khoá</button>
            )}
            {(c.status === 'ACTIVE' || c.status === 'LOCKED') && (
              <button className="btn btn-danger" disabled={busy} onClick={() => setConfirm('revoke')}><IconBan size={16} /> Thu hồi</button>
            )}
            {inserted && c.status !== 'PENDING' && (
              <button className="btn" disabled={busy} onClick={checkRsa}><IconShield size={16} /> Kiểm tra thẻ thật/giả</button>
            )}
            {c.status === 'PENDING' && inserted && (
              <button className="btn btn-primary" disabled={busy} onClick={activate}>Hoàn tất kích hoạt</button>
            )}
            {c.status === 'PENDING' && (
              <button className="btn" disabled={busy} onClick={removePending}>Xoá bản ghi chờ</button>
            )}
            {busy && <IconSpinner />}
          </div>
          {c.status === 'REVOKED' && <p className="muted" style={{ marginTop: 10 }}>Thẻ đã thu hồi vĩnh viễn.</p>}
        </section>
      </div>

      <section className="panel" style={{ marginTop: 16 }}>
        <h2>Bản sao lưu két</h2>
        {d.backups.length === 0 ? (
          <div className="empty">Chưa có bản sao lưu</div>
        ) : (
          <table>
            <thead><tr><th>Thời gian</th><th className="num">Số bản ghi</th><th className="num">Dung lượng</th></tr></thead>
            <tbody>
              {d.backups.map((b) => (
                <tr key={b.id}><td>{fmtDateTime(b.createdAt)}</td><td className="num">{b.entries}</td><td className="num">{fmtBytes(b.size)}</td></tr>
              ))}
            </tbody>
          </table>
        )}
        <p className="muted" style={{ fontSize: 12.5, marginTop: 8, marginBottom: 0 }}>
          Bản sao lưu được mã hoá trên thẻ bằng passphrase của chủ thẻ - admin không đọc được nội dung.
        </p>
      </section>

      <section className="panel">
        <div className="panel-head">
          <h2>Nhật ký gần đây</h2>
          <Link to={`/logs?cardId=${c.cardId}`}>Xem tất cả</Link>
        </div>
        <LogTable logs={d.logs} showCard={false} />
      </section>

      {confirm && (
        <ConfirmDialog kind={confirm} cardId={c.cardId} onCard={inserted} onCancel={() => setConfirm(null)} onConfirm={(r) => doAction(confirm, r)} />
      )}
    </>
  )
}

function ConfirmDialog({ kind, cardId, onCard, onCancel, onConfirm }: {
  kind: Kind; cardId: string; onCard: boolean; onCancel: () => void; onConfirm: (reason: string) => void
}) {
  const [reason, setReason] = useState('')
  const [typed, setTyped] = useState('')
  const revoke = kind === 'revoke'
  const ok = !revoke || (typed.trim().toUpperCase() === cardId && reason.trim().length > 0)
  return (
    <Modal title={`${KIND_LABEL[kind]} ${cardId}?`} onClose={onCancel}>
      {revoke && (
        <Alert tone="critical">
          Thu hồi là <strong>vĩnh viễn</strong>: thẻ xoá Master Key nên dữ liệu trên thẻ không giải mã được nữa. Chủ thẻ cần thẻ mới
          và khôi phục từ bản sao lưu.
        </Alert>
      )}
      <p className="ink-2">
        {onCard ? 'Thao tác sẽ được ghi lên thẻ đang cắm.' : 'Thẻ không cắm: chỉ cập nhật CSDL, đồng bộ lên thẻ ở lần kết nối sau.'}
      </p>
      <div className="grid" style={{ gap: 12 }}>
        <Field label={revoke ? 'Lý do (bắt buộc)' : 'Lý do (tuỳ chọn)'}>
          <input className="input" value={reason} onChange={(e) => setReason(e.target.value)} maxLength={120} placeholder="Ví dụ: chủ thẻ báo mất" />
        </Field>
        {revoke && (
          <Field label={`Gõ ${cardId} để xác nhận`}>
            <input className="input mono" value={typed} onChange={(e) => setTyped(e.target.value)} />
          </Field>
        )}
      </div>
      <div className="btn-row">
        <button className="btn" onClick={onCancel}>Huỷ</button>
        <button className={`btn ${revoke ? 'btn-danger' : 'btn-primary'}`} disabled={!ok} onClick={() => onConfirm(reason.trim())}>
          {KIND_LABEL[kind]}
        </button>
      </div>
    </Modal>
  )
}
