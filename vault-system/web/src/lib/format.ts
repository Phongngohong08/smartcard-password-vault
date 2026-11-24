// Nhãn tiếng Việt và định dạng hiển thị.

export const STATUS_LABEL: Record<string, string> = {
  PENDING: 'Chờ kích hoạt',
  ACTIVE: 'Hoạt động',
  LOCKED: 'Bị khoá',
  REVOKED: 'Đã thu hồi',
}

export const CARD_STATE_LABEL: Record<string, string> = {
  UNKNOWN: 'Chưa rõ',
  UNISSUED: 'Thẻ trắng',
  ACTIVE: 'Hoạt động',
  PIN_BLOCKED: 'Khoá PIN',
  ADMIN_LOCKED: 'Khoá admin',
  REVOKED: 'Thu hồi',
  DISABLED: 'Vô hiệu',
}

export const PENDING_LABEL: Record<string, string> = {
  NONE: '',
  LOCK: 'Chờ khoá trên thẻ',
  UNLOCK: 'Chờ mở khoá trên thẻ',
  REVOKE: 'Chờ thu hồi trên thẻ',
}

export const ACTION_LABEL: Record<string, string> = {
  ISSUE: 'Phát hành thẻ',
  LOGIN: 'Đăng nhập',
  LOGOUT: 'Đăng xuất',
  PIN_FAIL: 'Sai PIN',
  PIN_BLOCKED: 'Khoá PIN',
  PUK_UNBLOCK: 'Mở khoá bằng PUK',
  RSA_AUTH: 'Xác thực RSA',
  VIEW_PASSWORD: 'Xem mật khẩu',
  COPY_PASSWORD: 'Sao chép mật khẩu',
  ADD_ENTRY: 'Thêm bản ghi',
  EDIT_ENTRY: 'Sửa bản ghi',
  DELETE_ENTRY: 'Xoá bản ghi',
  CHANGE_PIN: 'Đổi PIN',
  LOCK: 'Khoá thẻ',
  UNLOCK: 'Mở khoá thẻ',
  REVOKE: 'Thu hồi thẻ',
  BACKUP: 'Sao lưu',
  RESTORE: 'Khôi phục',
  CARD_DISABLED: 'Thẻ vô hiệu',
  ADMIN_LOGIN: 'Admin đăng nhập',
  ADMIN_PASSWORD: 'Admin đổi mật khẩu',
}

const dateTimeFmt = new Intl.DateTimeFormat('vi-VN', {
  day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit',
})
const dateFmt = new Intl.DateTimeFormat('vi-VN', { day: '2-digit', month: '2-digit', year: 'numeric' })

export function fmtDateTime(iso: string | null | undefined): string {
  return iso ? dateTimeFmt.format(new Date(iso)) : '—'
}

export function fmtDate(iso: string | null | undefined): string {
  return iso ? dateFmt.format(new Date(iso)) : '—'
}

export function fmtRelative(iso: string | null | undefined): string {
  if (!iso) return 'chưa bao giờ'
  const s = Math.round((Date.now() - new Date(iso).getTime()) / 1000)
  if (s < 60) return 'vừa xong'
  if (s < 3600) return `${Math.floor(s / 60)} phút trước`
  if (s < 86400) return `${Math.floor(s / 3600)} giờ trước`
  return `${Math.floor(s / 86400)} ngày trước`
}

export function fmtNumber(n: number): string {
  return new Intl.NumberFormat('vi-VN').format(n)
}

export function fmtBytes(n: number): string {
  return n < 1024 ? `${n} B` : `${(n / 1024).toFixed(1)} KB`
}

/** Số byte UTF-8 (thẻ giới hạn theo byte, không theo ký tự). */
export function utf8Len(s: string): number {
  return new TextEncoder().encode(s).length
}

export function actorLabel(actor: string): string {
  if (actor.startsWith('admin:')) return `Admin ${actor.slice(6)}`
  if (actor.startsWith('card:')) return `Thẻ ${actor.slice(5)}`
  return actor
}
