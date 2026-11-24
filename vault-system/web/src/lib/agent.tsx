// Gọi Card Agent chạy trên máy admin (cầu nối trình duyệt <-> thẻ).
import { createContext, useCallback, useContext, useEffect, useRef, useState, type ReactNode } from 'react'
import { getToken } from './api'

export const AGENT_URL: string = import.meta.env.VITE_AGENT_URL ?? 'http://127.0.0.1:8765'

export type CardStateName = 'UNISSUED' | 'ACTIVE' | 'PIN_BLOCKED' | 'ADMIN_LOCKED' | 'REVOKED' | 'DISABLED' | 'UNKNOWN'

export interface AgentCard {
  present: boolean
  state?: number
  stateName?: CardStateName
  cardId?: string | null
  pinTriesLeft?: number
  pukTriesLeft?: number
  error?: string
  code?: string
}

export interface AgentHealth {
  ok: boolean
  version: string
  reader: string
  dev: boolean
}

export interface IssueRequest {
  cardId: string
  pin: string
  puk: string
  profile: { name: string; dob?: string; email?: string; phone?: string }
  avatarBase64?: string
}

export class AgentError extends Error {
  constructor(public code: string, message: string, public sw?: string) {
    super(message)
  }
}

async function call<T>(method: string, path: string, body?: unknown, withToken = false): Promise<T> {
  const headers: Record<string, string> = {}
  if (body !== undefined) headers['Content-Type'] = 'application/json'
  const token = getToken()
  if (withToken && token) headers.Authorization = `Bearer ${token}`
  let res: Response
  try {
    res = await fetch(AGENT_URL + path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) })
  } catch {
    throw new AgentError('AGENT_DOWN', `Không kết nối được Card Agent ở ${AGENT_URL}. Hãy chạy scripts\\agent.ps1.`)
  }
  const data = (await res.json().catch(() => ({}))) as Record<string, unknown>
  if (!res.ok) throw new AgentError(String(data.code ?? 'AGENT_ERROR'), String(data.error ?? `Agent lỗi HTTP ${res.status}`), data.sw as string | undefined)
  return data as T
}

export const agent = {
  health: () => call<AgentHealth>('GET', '/health'),
  card: () => call<AgentCard>('GET', '/card'),
  issue: (req: IssueRequest) =>
    call<{ cardId: string; modulusHex: string; exponentHex: string; steps: string[] }>('POST', '/card/issue', req, true),
  sign: (challenge: string) => call<{ cardId: string; signature: string }>('POST', '/card/sign', { challenge }),
  admin: (cardId: string, action: 'LOCK' | 'UNLOCK' | 'REVOKE') =>
    call<AgentCard>('POST', '/card/admin', { cardId, action }, true),
  blankCard: () => call<AgentCard>('POST', '/dev/blank-card', {}),
}

// ---------------------------------------------------------------- trạng thái agent dùng chung

interface AgentContextValue {
  online: boolean | null // null = đang kiểm tra
  health: AgentHealth | null
  card: AgentCard | null
  refresh: () => Promise<AgentCard | null>
  /** Tạm dừng thăm dò trong lúc một thao tác dài đang chạy trên thẻ. */
  setBusy: (busy: boolean) => void
}

const AgentContext = createContext<AgentContextValue | null>(null)

export function AgentProvider({ children }: { children: ReactNode }) {
  const [online, setOnline] = useState<boolean | null>(null)
  const [health, setHealth] = useState<AgentHealth | null>(null)
  const [card, setCard] = useState<AgentCard | null>(null)
  const busy = useRef(false)

  const refresh = useCallback(async () => {
    try {
      const [h, c] = await Promise.all([agent.health(), agent.card()])
      setHealth(h)
      setCard(c)
      setOnline(true)
      return c
    } catch {
      setOnline(false)
      setHealth(null)
      setCard(null)
      return null
    }
  }, [])

  useEffect(() => {
    void refresh()
    const id = window.setInterval(() => {
      if (!busy.current && document.visibilityState === 'visible') void refresh()
    }, 4000)
    return () => window.clearInterval(id)
  }, [refresh])

  const setBusy = useCallback((b: boolean) => {
    busy.current = b
  }, [])

  return <AgentContext.Provider value={{ online, health, card, refresh, setBusy }}>{children}</AgentContext.Provider>
}

export function useAgent(): AgentContextValue {
  const v = useContext(AgentContext)
  if (!v) throw new Error('useAgent phải nằm trong AgentProvider')
  return v
}

/** Thẻ đang cắm (đã phát hành) có đúng mã này không. */
export function isInserted(card: AgentCard | null, cardId: string): boolean {
  return !!card?.present && card.cardId === cardId
}
