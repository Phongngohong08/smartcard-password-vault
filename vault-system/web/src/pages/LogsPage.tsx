import { useEffect, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import LogTable from '../components/LogTable'
import { Alert, Field } from '../components/ui'
import { api, ApiError, type LogPage } from '../lib/api'
import { ACTION_LABEL, fmtNumber } from '../lib/format'

const SIZE = 50
const KEYS = ['cardId', 'action', 'result', 'from', 'to'] as const

export default function LogsPage() {
  const [params, setParams] = useSearchParams()
  const [page, setPage] = useState<LogPage | null>(null)
  const [error, setError] = useState<string | null>(null)
  const pageNo = Number(params.get('page') ?? '1') || 1

  useEffect(() => {
    const t = window.setTimeout(async () => {
      const q: Record<string, string | number> = { page: pageNo, size: SIZE }
      for (const k of KEYS) {
        const v = params.get(k)
        if (v) q[k] = v
      }
      try {
        setPage(await api.logs(q))
        setError(null)
      } catch (e) {
        setError(e instanceof ApiError ? e.message : 'Không tải được nhật ký')
      }
    }, 200)
    return () => window.clearTimeout(t)
  }, [params, pageNo])

  function setParam(k: string, v: string) {
    const p = new URLSearchParams(params)
    if (v) p.set(k, v)
    else p.delete(k)
    if (k !== 'page') p.delete('page')
    setParams(p, { replace: true })
  }

  const pages = page ? Math.max(1, Math.ceil(page.total / SIZE)) : 1

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Nhật ký</h1>
          <p>Mọi thao tác của admin và của thẻ. Nhật ký không bao giờ chứa mật khẩu hay PIN.</p>
        </div>
      </div>
      {error && <Alert tone="critical">{error}</Alert>}
      <section className="panel">
        <div className="filters">
          <Field label="Mã thẻ">
            <input className="input mono" value={params.get('cardId') ?? ''} maxLength={8}
              onChange={(e) => setParam('cardId', e.target.value.toUpperCase())} />
          </Field>
          <Field label="Thao tác">
            <select className="input" value={params.get('action') ?? ''} onChange={(e) => setParam('action', e.target.value)}>
              <option value="">Tất cả</option>
              {Object.entries(ACTION_LABEL).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
            </select>
          </Field>
          <Field label="Kết quả">
            <select className="input" value={params.get('result') ?? ''} onChange={(e) => setParam('result', e.target.value)}>
              <option value="">Tất cả</option>
              <option value="OK">Thành công</option>
              <option value="FAIL">Thất bại</option>
            </select>
          </Field>
          <Field label="Từ ngày">
            <input className="input" type="date" value={params.get('from') ?? ''} onChange={(e) => setParam('from', e.target.value)} />
          </Field>
          <Field label="Đến ngày">
            <input className="input" type="date" value={params.get('to') ?? ''} onChange={(e) => setParam('to', e.target.value)} />
          </Field>
          {KEYS.some((k) => params.get(k)) && (
            <button className="btn btn-ghost" onClick={() => setParams({}, { replace: true })}>Bỏ lọc</button>
          )}
        </div>
        {page && <LogTable logs={page.items} />}
        {page && page.total > 0 && (
          <div className="pager">
            <span>{fmtNumber(page.total)} dòng · trang {pageNo}/{pages}</span>
            <div className="btn-row">
              <button className="btn btn-sm" disabled={pageNo <= 1} onClick={() => setParam('page', String(pageNo - 1))}>Trước</button>
              <button className="btn btn-sm" disabled={pageNo >= pages} onClick={() => setParam('page', String(pageNo + 1))}>Sau</button>
            </div>
          </div>
        )}
      </section>
    </>
  )
}
