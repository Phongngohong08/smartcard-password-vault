import { useEffect, useState } from 'react'
import { Link, useNavigate, useSearchParams } from 'react-router-dom'
import { IconPlus } from '../components/Icons'
import { Alert, CardStateBadge, Field, PendingBadge, StatusBadge } from '../components/ui'
import { api, ApiError, type Card } from '../lib/api'
import { isInserted, useAgent } from '../lib/agent'
import { fmtDate, fmtRelative, STATUS_LABEL } from '../lib/format'

export default function CardsPage() {
  const [params, setParams] = useSearchParams()
  const status = params.get('status') ?? ''
  const [q, setQ] = useState(params.get('q') ?? '')
  const [cards, setCards] = useState<Card[] | null>(null)
  const [error, setError] = useState<string | null>(null)
  const navigate = useNavigate()
  const { card: inserted } = useAgent()

  useEffect(() => {
    const t = window.setTimeout(async () => {
      try {
        setCards(await api.cards({ status, q }))
        setError(null)
      } catch (e) {
        setError(e instanceof ApiError ? e.message : 'Không tải được danh sách thẻ')
      }
    }, 200)
    return () => window.clearTimeout(t)
  }, [status, q])

  function setStatus(s: string) {
    const p = new URLSearchParams(params)
    if (s) p.set('status', s)
    else p.delete('status')
    setParams(p, { replace: true })
  }

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Thẻ</h1>
          <p>Mọi thẻ đã phát hành. Chọn một thẻ để khoá, mở khoá hoặc thu hồi.</p>
        </div>
        <Link className="btn btn-primary" to="/issue"><IconPlus size={16} /> Phát hành thẻ</Link>
      </div>
      {error && <Alert tone="critical">{error}</Alert>}
      <section className="panel">
        <div className="filters">
          <Field label="Tìm kiếm">
            <input className="input" placeholder="Mã thẻ, họ tên, email" value={q} onChange={(e) => setQ(e.target.value)} />
          </Field>
          <Field label="Trạng thái">
            <select className="input" value={status} onChange={(e) => setStatus(e.target.value)}>
              <option value="">Tất cả</option>
              {Object.entries(STATUS_LABEL).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
            </select>
          </Field>
        </div>
        {cards && cards.length === 0 && <div className="empty">Không có thẻ nào phù hợp</div>}
        {cards && cards.length > 0 && (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Mã thẻ</th>
                  <th>Chủ thẻ</th>
                  <th>Trạng thái</th>
                  <th>Trên thẻ</th>
                  <th>Ngày cấp</th>
                  <th>Lần cuối thấy</th>
                </tr>
              </thead>
              <tbody>
                {cards.map((c) => (
                  <tr key={c.cardId} className="clickable" onClick={() => navigate(`/cards/${c.cardId}`)}>
                    <td className="nowrap">
                      <Link to={`/cards/${c.cardId}`} className="mono" onClick={(e) => e.stopPropagation()}>{c.cardId}</Link>
                      {isInserted(inserted, c.cardId) && <span className="muted" style={{ fontSize: 12 }}> · đang cắm</span>}
                    </td>
                    <td>
                      {c.ownerName}
                      {c.ownerEmail && <div className="muted" style={{ fontSize: 12.5 }}>{c.ownerEmail}</div>}
                    </td>
                    <td><div className="btn-row"><StatusBadge status={c.status} /><PendingBadge action={c.pendingAction} /></div></td>
                    <td><CardStateBadge state={c.cardState} /></td>
                    <td className="nowrap ink-2">{fmtDate(c.issuedAt)}</td>
                    <td className="nowrap ink-2">{fmtRelative(c.lastSeenAt)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </>
  )
}
