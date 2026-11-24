// Các thành phần giao diện nhỏ dùng chung.
import { useEffect, type ReactNode } from 'react'
import { IconAlert, IconCheck, IconInfo } from './Icons'
import { ACTION_LABEL, CARD_STATE_LABEL, PENDING_LABEL, STATUS_LABEL } from '../lib/format'

type Tone = 'good' | 'warning' | 'critical' | 'info' | 'neutral'

export function Badge({ tone = 'neutral', children }: { tone?: Tone; children: ReactNode }) {
  return (
    <span className={`badge ${tone === 'neutral' ? '' : 'badge-' + tone}`}>
      <span className="dot" />
      {children}
    </span>
  )
}

const STATUS_TONE: Record<string, Tone> = { PENDING: 'info', ACTIVE: 'good', LOCKED: 'warning', REVOKED: 'critical' }
export function StatusBadge({ status }: { status: string }) {
  return <Badge tone={STATUS_TONE[status] ?? 'neutral'}>{STATUS_LABEL[status] ?? status}</Badge>
}

const CARD_STATE_TONE: Record<string, Tone> = {
  UNISSUED: 'info', ACTIVE: 'good', PIN_BLOCKED: 'warning', ADMIN_LOCKED: 'warning', REVOKED: 'critical', DISABLED: 'critical',
}
export function CardStateBadge({ state }: { state: string }) {
  return <Badge tone={CARD_STATE_TONE[state] ?? 'neutral'}>{CARD_STATE_LABEL[state] ?? state}</Badge>
}

export function PendingBadge({ action }: { action: string }) {
  if (action === 'NONE') return null
  return <Badge tone="warning">{PENDING_LABEL[action] ?? action}</Badge>
}

export function ResultBadge({ result }: { result: string }) {
  return result === 'OK' ? <Badge tone="good">Thành công</Badge> : <Badge tone="critical">Thất bại</Badge>
}

export function ActionLabel({ action }: { action: string }) {
  return <>{ACTION_LABEL[action] ?? action}</>
}

export function Alert({ tone = 'info', children }: { tone?: 'info' | 'good' | 'warning' | 'critical'; children: ReactNode }) {
  const icon = tone === 'good' ? <IconCheck /> : tone === 'info' ? <IconInfo /> : <IconAlert />
  return (
    <div className={`alert alert-${tone}`} role={tone === 'critical' ? 'alert' : 'status'}>
      {icon}
      <div>{children}</div>
    </div>
  )
}

export function Modal({ title, children, onClose }: { title: string; children: ReactNode; onClose: () => void }) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && onClose()
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [onClose])
  return (
    <div className="modal-back" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div className="modal" role="dialog" aria-modal="true" aria-label={title}>
        <h2>{title}</h2>
        {children}
      </div>
    </div>
  )
}

export function Field({ label, hint, error, children, className }: {
  label: string; hint?: ReactNode; error?: string | null; children: ReactNode; className?: string
}) {
  return (
    <div className={`field ${className ?? ''}`}>
      <label>{label}</label>
      {children}
      {error ? <span className="err">{error}</span> : hint ? <span className="hint">{hint}</span> : null}
    </div>
  )
}
