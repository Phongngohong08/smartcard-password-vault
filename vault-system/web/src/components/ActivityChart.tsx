// Biểu đồ cột chồng: số sự kiện thành công / thất bại mỗi ngày (7 ngày).
// Cột ≤ 24px, đầu cột bo 4px, khe 2px giữa hai đoạn, lưới mảnh; có chú giải, tooltip khi rê chuột và bảng số liệu.
// Vẽ theo đúng bề rộng thật của khung (đo bằng ResizeObserver) để chữ không bị co giãn trên màn hình hẹp.
import { useEffect, useRef, useState } from 'react'
import type { DailyCount } from '../lib/api'
import { fmtNumber } from '../lib/format'
import { IconAlert } from './Icons'

const H = 180 // chiều cao vùng vẽ (px)
const PAD_L = 36
const PAD_T = 8
const PAD_B = 26
const BAR = 22

/** Trục Y: bước tròn (1, 2, 5 x 10^n) sao cho có khoảng 4 vạch. */
function niceScale(maxValue: number): { max: number; step: number } {
  const v = Math.max(4, maxValue)
  const rough = v / 4
  const p = Math.pow(10, Math.floor(Math.log10(rough)))
  const n = rough / p
  const step = (n <= 1 ? 1 : n <= 2 ? 2 : n <= 5 ? 5 : 10) * p
  return { max: Math.ceil(v / step) * step, step }
}

function dayLabel(iso: string): string {
  const [, m, d] = iso.split('-')
  return `${d}/${m}`
}

/** Đường dẫn cột: bo 4px ở đầu trên, vuông ở đáy. */
function barPath(x: number, y: number, w: number, h: number, roundTop: boolean): string {
  const r = roundTop ? Math.min(4, h, w / 2) : 0
  return `M${x},${y + h} V${y + r} Q${x},${y} ${x + r},${y} H${x + w - r} Q${x + w},${y} ${x + w},${y + r} V${y + h} Z`
}

export default function ActivityChart({ data }: { data: DailyCount[] }) {
  const [hover, setHover] = useState<number | null>(null)
  const wrap = useRef<HTMLDivElement>(null)
  const [W, setW] = useState(600)

  useEffect(() => {
    const el = wrap.current
    if (!el) return
    const ro = new ResizeObserver(([e]) => setW(Math.max(260, Math.floor(e.contentRect.width))))
    ro.observe(el)
    return () => ro.disconnect()
  }, [])

  const { max, step } = niceScale(Math.max(...data.map((d) => d.ok + d.fail)))
  const slot = (W - PAD_L) / data.length
  const y = (v: number) => PAD_T + H - (v / max) * H
  const ticks: number[] = []
  for (let t = 0; t <= max; t += step) ticks.push(t)
  const tip = hover === null ? null : data[hover]

  return (
    <div>
      <div className="chart-legend" aria-hidden="true">
        <span><i className="swatch" style={{ background: 'var(--series-ok)' }} /> Thành công</span>
        <span><i className="swatch" style={{ background: 'var(--critical)' }} /> <IconAlert size={13} /> Thất bại</span>
      </div>
      <div className="chart-wrap" ref={wrap} onMouseLeave={() => setHover(null)}>
        <svg width={W} height={PAD_T + H + PAD_B} role="img" style={{ display: 'block', marginTop: 8 }}
          aria-label="Số sự kiện thành công và thất bại theo ngày trong 7 ngày gần nhất">
          {ticks.map((t) => (
            <g key={t}>
              <line x1={PAD_L} x2={W} y1={y(t)} y2={y(t)} stroke={t === 0 ? 'var(--axis)' : 'var(--line)'} strokeWidth={1} />
              <text x={PAD_L - 8} y={y(t) + 4} textAnchor="end" fontSize="11" fill="var(--muted)"
                style={{ fontVariantNumeric: 'tabular-nums' }}>{fmtNumber(t)}</text>
            </g>
          ))}
          {data.map((d, i) => {
            const cx = PAD_L + slot * i + slot / 2
            const x = cx - BAR / 2
            const okH = (d.ok / max) * H
            const failH = (d.fail / max) * H
            const gap = d.ok > 0 && d.fail > 0 ? 2 : 0
            return (
              <g key={d.date}>
                {/* vùng rê chuột rộng bằng cả cột ngày, lớn hơn thanh */}
                <rect x={PAD_L + slot * i} y={PAD_T} width={slot} height={H}
                  fill={hover === i ? 'var(--surface-2)' : 'transparent'} onMouseEnter={() => setHover(i)} />
                {d.ok > 0 && <path d={barPath(x, y(d.ok), BAR, okH, d.fail === 0)} fill="var(--series-ok)" pointerEvents="none" />}
                {d.fail > 0 && (
                  <path d={barPath(x, y(d.ok) - gap - failH, BAR, failH, true)} fill="var(--critical)" pointerEvents="none" />
                )}
                <text x={cx} y={PAD_T + H + 18} textAnchor="middle" fontSize="11" fill="var(--muted)">{dayLabel(d.date)}</text>
              </g>
            )
          })}
        </svg>
        {tip && hover !== null && (
          <div className="chart-tip" style={{
            left: Math.min(Math.max(PAD_L + slot * hover + slot / 2, 70), W - 70),
            top: Math.max(4, y(tip.ok + tip.fail) - 6),
          }}>
            <div style={{ fontWeight: 600, marginBottom: 4 }}>Ngày {dayLabel(tip.date)}</div>
            <div className="row"><i className="swatch" style={{ background: 'var(--series-ok)' }} />Thành công <strong>{fmtNumber(tip.ok)}</strong></div>
            <div className="row"><i className="swatch" style={{ background: 'var(--critical)' }} />Thất bại <strong>{fmtNumber(tip.fail)}</strong></div>
          </div>
        )}
      </div>
      <details className="table-view">
        <summary>Xem bảng số liệu</summary>
        <table>
          <thead><tr><th>Ngày</th><th className="num">Thành công</th><th className="num">Thất bại</th></tr></thead>
          <tbody>
            {data.map((d) => (
              <tr key={d.date}><td>{dayLabel(d.date)}</td><td className="num">{d.ok}</td><td className="num">{d.fail}</td></tr>
            ))}
          </tbody>
        </table>
      </details>
    </div>
  )
}
