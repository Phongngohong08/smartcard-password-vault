import { Link } from 'react-router-dom'
import type { LogEntry } from '../lib/api'
import { actorLabel, fmtDateTime } from '../lib/format'
import { ActionLabel, ResultBadge } from './ui'

export default function LogTable({ logs, showCard = true }: { logs: LogEntry[]; showCard?: boolean }) {
  if (logs.length === 0) return <div className="empty">Chưa có nhật ký</div>
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Thời gian</th>
            {showCard && <th>Thẻ</th>}
            <th>Thao tác</th>
            <th>Kết quả</th>
            <th>Người thực hiện</th>
            <th>Chi tiết</th>
          </tr>
        </thead>
        <tbody>
          {logs.map((l) => (
            <tr key={l.id}>
              <td className="nowrap ink-2">{fmtDateTime(l.createdAt)}</td>
              {showCard && (
                <td className="nowrap">{l.cardId ? <Link to={`/cards/${l.cardId}`} className="mono">{l.cardId}</Link> : <span className="muted">—</span>}</td>
              )}
              <td className="nowrap"><ActionLabel action={l.action} /></td>
              <td><ResultBadge result={l.result} /></td>
              <td className="nowrap ink-2">{actorLabel(l.actor)}</td>
              <td className="ink-2">{l.detail ?? ''}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
