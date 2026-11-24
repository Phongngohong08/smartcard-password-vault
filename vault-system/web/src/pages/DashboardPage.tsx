import { useEffect, useState, type ReactNode } from 'react'
import { Link } from 'react-router-dom'
import ActivityChart from '../components/ActivityChart'
import { IconAlert, IconRefresh } from '../components/Icons'
import LogTable from '../components/LogTable'
import { Alert } from '../components/ui'
import { api, ApiError, type Stats } from '../lib/api'
import { fmtNumber } from '../lib/format'

export default function DashboardPage() {
  const [stats, setStats] = useState<Stats | null>(null)
  const [error, setError] = useState<string | null>(null)

  async function load() {
    try {
      setStats(await api.stats())
      setError(null)
    } catch (e) {
      setError(e instanceof ApiError ? e.message : 'Không tải được số liệu')
    }
  }

  useEffect(() => {
    void load()
    const id = window.setInterval(load, 15000)
    return () => window.clearInterval(id)
  }, [])

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Tổng quan</h1>
          <p>Tình trạng các thẻ và hoạt động 24 giờ qua</p>
        </div>
        <button className="btn" onClick={load}><IconRefresh size={16} /> Làm mới</button>
      </div>
      {error && <Alert tone="critical">{error}</Alert>}
      {stats && (
        <>
          {stats.last24h.rsaFail > 0 && (
            <Alert tone="critical">
              <strong>{stats.last24h.rsaFail} lần xác thực RSA thất bại trong 24 giờ</strong> - có thể có thẻ giả.{' '}
              <Link to="/logs?action=RSA_AUTH&result=FAIL">Xem nhật ký</Link>
            </Alert>
          )}
          {stats.cards.pendingSync > 0 && (
            <Alert tone="warning">
              {stats.cards.pendingSync} thẻ có thao tác admin chưa ghi lên thẻ (thẻ không cắm lúc thao tác). Thao tác sẽ được
              đồng bộ ở lần thẻ kết nối tiếp theo.
            </Alert>
          )}

          <div className="tiles">
            <Tile label="Tổng số thẻ" value={stats.cards.total} sub={`${stats.cards.byStatus.PENDING} chờ kích hoạt`} />
            <Tile label="Đang hoạt động" value={stats.cards.byStatus.ACTIVE}
              sub={stats.cards.pinBlocked ? `${stats.cards.pinBlocked} thẻ đang khoá PIN` : 'Không có thẻ khoá PIN'} />
            <Tile label="Bị admin khoá" value={stats.cards.byStatus.LOCKED} />
            <Tile label="Đã thu hồi" value={stats.cards.byStatus.REVOKED} />
          </div>
          <div className="tiles">
            <Tile label="Đăng nhập (24 giờ)" value={stats.last24h.logins} />
            <Tile label="Nhập sai PIN (24 giờ)" value={stats.last24h.pinFail} />
            <Tile label="RSA thất bại (24 giờ)" value={stats.last24h.rsaFail}
              sub={stats.last24h.rsaFail > 0 ? <><IconAlert size={13} /> Cần kiểm tra</> : 'Không có thẻ giả'} />
            <Tile label="Sự kiện (24 giờ)" value={stats.last24h.events} />
          </div>

          <div className="grid grid-3">
            <section className="panel">
              <div className="panel-head"><h2>Hoạt động 7 ngày</h2></div>
              <ActivityChart data={stats.daily} />
            </section>
            <section className="panel">
              <div className="panel-head"><h2>Thao tác nhanh</h2></div>
              <div className="grid" style={{ gap: 8 }}>
                <Link className="btn btn-primary" to="/issue">Phát hành thẻ mới</Link>
                <Link className="btn" to="/cards?status=LOCKED">Thẻ đang bị khoá</Link>
                <Link className="btn" to="/logs?result=FAIL">Các thao tác thất bại</Link>
              </div>
            </section>
          </div>

          <section className="panel" style={{ marginTop: 16 }}>
            <div className="panel-head">
              <h2>Hoạt động gần đây</h2>
              <Link to="/logs">Xem tất cả</Link>
            </div>
            <LogTable logs={stats.recentLogs} />
          </section>
        </>
      )}
    </>
  )
}

function Tile({ label, value, sub }: { label: string; value: number; sub?: ReactNode }) {
  return (
    <div className="tile">
      <div className="tile-label">{label}</div>
      <div className="tile-value">{fmtNumber(value)}</div>
      {sub && <div className="tile-sub">{sub}</div>}
    </div>
  )
}
