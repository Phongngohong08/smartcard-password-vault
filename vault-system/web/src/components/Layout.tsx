import { NavLink, Outlet } from 'react-router-dom'
import { useAgent } from '../lib/agent'
import { CARD_STATE_LABEL } from '../lib/format'
import { IconCard, IconDashboard, IconLog, IconLogout, IconPlus, IconUser } from './Icons'

const NAV = [
  { to: '/', label: 'Tổng quan', icon: <IconDashboard />, end: true },
  { to: '/cards', label: 'Thẻ', icon: <IconCard /> },
  { to: '/issue', label: 'Phát hành thẻ', icon: <IconPlus /> },
  { to: '/logs', label: 'Nhật ký', icon: <IconLog /> },
  { to: '/account', label: 'Tài khoản', icon: <IconUser /> },
]

export default function Layout({ user, onLogout }: { user: string; onLogout: () => void }) {
  return (
    <div className="shell">
      <aside className="sidebar">
        <div className="brand">
          <span style={{ color: 'var(--accent)', display: 'inline-flex' }}><IconCard size={26} /></span>
          <div>
            Vault Admin
            <small>Quản lý mật khẩu bằng Smart Card</small>
          </div>
        </div>
        {NAV.map((n) => (
          <NavLink key={n.to} to={n.to} end={n.end} className={({ isActive }) => `nav-link${isActive ? ' active' : ''}`}>
            {n.icon}
            {n.label}
          </NavLink>
        ))}
        <div className="sidebar-foot">
          <div style={{ marginBottom: 8 }}>
            Đăng nhập: <strong>{user}</strong>
          </div>
          <button className="btn btn-sm" onClick={onLogout}>
            <IconLogout size={16} /> Đăng xuất
          </button>
        </div>
      </aside>
      <div className="main">
        <header className="topbar">
          <AgentPill />
        </header>
        <main className="content">
          <Outlet />
        </main>
      </div>
    </div>
  )
}

/** Trạng thái Card Agent và thẻ đang cắm, luôn hiện ở thanh trên. */
function AgentPill() {
  const { online, card } = useAgent()
  let color = 'var(--muted)'
  let text = 'Đang kiểm tra Card Agent...'
  if (online === false) {
    color = 'var(--critical)'
    text = 'Card Agent chưa chạy'
  } else if (online && !card?.present) {
    color = 'var(--warning)'
    text = card?.code === 'READER_BUSY' ? 'Đầu đọc đang bận' : 'Agent sẵn sàng · chưa có thẻ'
  } else if (online && card?.present) {
    color = 'var(--good)'
    const st = CARD_STATE_LABEL[card.stateName ?? 'UNKNOWN'] ?? card.stateName
    text = card.cardId ? `Thẻ ${card.cardId} · ${st}` : `Thẻ trắng (chưa phát hành)`
  }
  return (
    <span className="agent-pill" title={card?.error ?? ''}>
      <span className="dot" style={{ background: color }} />
      {text}
    </span>
  )
}
