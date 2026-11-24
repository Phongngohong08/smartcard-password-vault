// Bộ icon nét mảnh (SVG nội tuyến, kế thừa màu chữ).
import type { ReactNode } from 'react'

function Svg({ children, size = 18 }: { children: ReactNode; size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.8}
      strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      {children}
    </svg>
  )
}

type P = { size?: number }

export const IconDashboard = (p: P) => (
  <Svg {...p}><rect x="3" y="3" width="7" height="9" rx="1.5" /><rect x="14" y="3" width="7" height="5" rx="1.5" /><rect x="14" y="12" width="7" height="9" rx="1.5" /><rect x="3" y="16" width="7" height="5" rx="1.5" /></Svg>
)
export const IconCard = (p: P) => (
  <Svg {...p}><rect x="2.5" y="5" width="19" height="14" rx="2.5" /><rect x="5.5" y="9" width="5" height="4" rx="0.8" /><path d="M14 15h4" /></Svg>
)
export const IconPlus = (p: P) => (
  <Svg {...p}><path d="M12 5v14M5 12h14" /></Svg>
)
export const IconLog = (p: P) => (
  <Svg {...p}><path d="M8 6h12M8 12h12M8 18h12" /><circle cx="4" cy="6" r="0.6" fill="currentColor" /><circle cx="4" cy="12" r="0.6" fill="currentColor" /><circle cx="4" cy="18" r="0.6" fill="currentColor" /></Svg>
)
export const IconUser = (p: P) => (
  <Svg {...p}><circle cx="12" cy="8" r="4" /><path d="M4 21c0-4 3.6-6.5 8-6.5s8 2.5 8 6.5" /></Svg>
)
export const IconLock = (p: P) => (
  <Svg {...p}><rect x="4.5" y="10.5" width="15" height="10" rx="2" /><path d="M8 10.5V7a4 4 0 0 1 8 0v3.5" /></Svg>
)
export const IconUnlock = (p: P) => (
  <Svg {...p}><rect x="4.5" y="10.5" width="15" height="10" rx="2" /><path d="M8 10.5V7a4 4 0 0 1 7.5-2" /></Svg>
)
export const IconBan = (p: P) => (
  <Svg {...p}><circle cx="12" cy="12" r="9" /><path d="M5.6 5.6l12.8 12.8" /></Svg>
)
export const IconShield = (p: P) => (
  <Svg {...p}><path d="M12 3l8 3v6c0 4.5-3.4 8.2-8 9-4.6-.8-8-4.5-8-9V6l8-3z" /><path d="M8.5 12l2.5 2.5 4.5-5" /></Svg>
)
export const IconCheck = (p: P) => (
  <Svg {...p}><path d="M5 12.5l4.5 4.5L19 7.5" /></Svg>
)
export const IconX = (p: P) => (
  <Svg {...p}><path d="M6 6l12 12M18 6L6 18" /></Svg>
)
export const IconAlert = (p: P) => (
  <Svg {...p}><path d="M12 3.5l9.5 16.5h-19L12 3.5z" /><path d="M12 10v4.5" /><circle cx="12" cy="17.3" r="0.6" fill="currentColor" /></Svg>
)
export const IconInfo = (p: P) => (
  <Svg {...p}><circle cx="12" cy="12" r="9" /><path d="M12 11v5.5" /><circle cx="12" cy="7.8" r="0.6" fill="currentColor" /></Svg>
)
export const IconRefresh = (p: P) => (
  <Svg {...p}><path d="M20 11a8 8 0 0 0-14.3-4.6M4 13a8 8 0 0 0 14.3 4.6" /><path d="M5 3v4h4M19 21v-4h-4" /></Svg>
)
export const IconSpinner = (p: P) => (
  <span className="spin" style={{ display: 'inline-flex' }}>
    <Svg {...p}><path d="M12 3a9 9 0 1 1-9 9" /></Svg>
  </span>
)
export const IconLogout = (p: P) => (
  <Svg {...p}><path d="M15 4h3a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2h-3" /><path d="M10 16l-4-4 4-4M6 12h10" /></Svg>
)
export const IconSync = (p: P) => (
  <Svg {...p}><path d="M4 12a8 8 0 0 1 13.7-5.7L20 8.5M20 12a8 8 0 0 1-13.7 5.7L4 15.5" /><path d="M20 4v4.5h-4.5M4 20v-4.5h4.5" /></Svg>
)
