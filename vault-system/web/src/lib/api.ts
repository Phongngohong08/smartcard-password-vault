// Gọi Vault server (qua /api; khi dev Vite proxy sang :8080).

export type CardStatus = 'PENDING' | 'ACTIVE' | 'LOCKED' | 'REVOKED'
export type PendingAction = 'NONE' | 'LOCK' | 'UNLOCK' | 'REVOKE'

export interface Card {
  cardId: string
  ownerName: string
  ownerEmail: string | null
  ownerPhone: string | null
  status: CardStatus
  cardState: string
  pendingAction: PendingAction
  replacesCardId: string | null
  issuedBy: string | null
  issuedAt: string | null
  revokedAt: string | null
  lastSeenAt: string | null
  createdAt: string
  keyFingerprint: string
}

export interface LogEntry {
  id: number
  cardId: string | null
  actor: string
  action: string
  result: 'OK' | 'FAIL'
  detail: string | null
  ip: string | null
  createdAt: string
}

export interface LogPage {
  items: LogEntry[]
  total: number
  page: number
  size: number
}

export interface BackupInfo {
  id: number
  cardId: string
  entries: number
  size: number
  createdAt: string
}

export interface CardDetail {
  card: Card
  modulusHex: string
  exponentHex: string
  replacedBy: string | null
  logs: LogEntry[]
  backups: BackupInfo[]
}

export interface DailyCount {
  date: string
  ok: number
  fail: number
}

export interface Stats {
  cards: { total: number; byStatus: Record<CardStatus, number>; pendingSync: number; pinBlocked: number }
  last24h: { events: number; rsaFail: number; pinFail: number; logins: number }
  daily: DailyCount[]
  recentLogs: LogEntry[]
}

export interface RegisterCardRequest {
  cardId: string
  ownerName: string
  ownerEmail?: string
  ownerPhone?: string
  modulusHex: string
  exponentHex: string
  replacesCardId?: string
}

export class ApiError extends Error {
  constructor(
    public status: number,
    public code: string,
    message: string,
    public data?: Record<string, unknown>,
  ) {
    super(message)
  }
}

// ---------------------------------------------------------------- phiên đăng nhập
// Token để trong sessionStorage: đóng tab là phải đăng nhập lại.

const TOKEN_KEY = 'vault.admin.token'
const USER_KEY = 'vault.admin.user'

export function getToken(): string | null {
  try {
    return sessionStorage.getItem(TOKEN_KEY)
  } catch {
    return null
  }
}

export function getUsername(): string | null {
  try {
    return getToken() ? sessionStorage.getItem(USER_KEY) : null
  } catch {
    return null
  }
}

export function saveSession(token: string | null, username?: string) {
  try {
    if (token) {
      sessionStorage.setItem(TOKEN_KEY, token)
      sessionStorage.setItem(USER_KEY, username ?? '')
    } else {
      sessionStorage.removeItem(TOKEN_KEY)
      sessionStorage.removeItem(USER_KEY)
    }
  } catch {
    // trình duyệt chặn storage: phiên chỉ sống trong bộ nhớ
  }
}

async function request<T>(method: string, path: string, body?: unknown, auth = true): Promise<T> {
  const headers: Record<string, string> = {}
  if (body !== undefined) headers['Content-Type'] = 'application/json'
  const token = getToken()
  if (auth && token) headers.Authorization = `Bearer ${token}`

  let res: Response
  try {
    res = await fetch(`/api${path}`, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) })
  } catch {
    throw new ApiError(0, 'SERVER_DOWN', 'Không kết nối được Vault server')
  }
  const text = await res.text()
  let data: unknown = null
  try {
    data = text ? JSON.parse(text) : null
  } catch {
    data = null
  }
  if (!res.ok) {
    const d = (data ?? {}) as Record<string, unknown>
    if (res.status === 401 && auth) {
      saveSession(null)
      window.dispatchEvent(new Event('vault:logout'))
    }
    throw new ApiError(res.status, String(d.code ?? 'HTTP_' + res.status), String(d.error ?? `Lỗi HTTP ${res.status}`), d)
  }
  return data as T
}

function qs(params: Record<string, string | number | undefined>): string {
  const p = new URLSearchParams()
  for (const [k, v] of Object.entries(params)) if (v !== undefined && v !== '') p.set(k, String(v))
  const s = p.toString()
  return s ? `?${s}` : ''
}

export const api = {
  login: (username: string, password: string) =>
    request<{ token: string; username: string; expiresAt: string }>('POST', '/admin/login', { username, password }, false),
  changePassword: (oldPassword: string, newPassword: string) =>
    request<{ ok: boolean }>('POST', '/admin/password', { oldPassword, newPassword }),

  stats: () => request<Stats>('GET', '/stats'),
  cards: (params: { status?: string; q?: string } = {}) => request<Card[]>('GET', `/cards${qs(params)}`),
  nextCardId: () => request<{ cardId: string }>('GET', '/cards/next-id'),
  card: (id: string) => request<CardDetail>('GET', `/cards/${id}`),
  registerCard: (req: RegisterCardRequest) => request<Card>('POST', '/cards', req),
  activate: (id: string, challenge: string, signature: string) =>
    request<Card>('POST', `/cards/${id}/activate`, { challenge, signature }),
  deletePending: (id: string) => request<{ ok: boolean }>('DELETE', `/cards/${id}`),
  cardAction: (id: string, action: 'lock' | 'unlock' | 'revoke', onCard: boolean, reason?: string) =>
    request<Card>('POST', `/cards/${id}/${action}`, { onCard, reason }),
  logs: (params: Record<string, string | number | undefined>) => request<LogPage>('GET', `/logs${qs(params)}`),

  // Xác thực thẻ bằng RSA (API công khai, app người dùng cũng dùng)
  challenge: (cardId: string) =>
    request<{ challenge: string; expiresIn: number; status: CardStatus; pendingAction: PendingAction }>(
      'POST', '/auth/challenge', { cardId }, false),
  verify: (cardId: string, challenge: string, signature: string) =>
    request<{ token: string; card: { cardId: string; ownerName: string; status: CardStatus } }>(
      'POST', '/auth/verify', { cardId, challenge, signature }, false),
}
