# Vault system: server, web quản trị, card agent

Phần mềm cho đồ án "Quản lý mật khẩu bằng Smart Card". Applet nằm ở `..\PasswordVault`.

```
Web quản trị (React)  ──/api──▶  Vault server (Go) ──▶ MySQL
        │                              ▲
        └──▶ Card Agent (Java) ────────┘  lấy adminKey / phản hồi ADMIN_AUTH (token admin)
                  │ APDU
            Simulator hoặc đầu đọc thẻ
```

| Thư mục | Thành phần | Cổng |
|---|---|---|
| `server/` | API + phục vụ web đã build. Go, MySQL, JWT, bcrypt | 8080 |
| `web/` | Web quản trị. React + TypeScript + Vite | 5173 khi dev |
| `agent/` | Cầu nối trình duyệt ↔ thẻ. Java, dùng lại `VaultCard.java` của bộ test applet | 8765 |
| `scripts/` | Cài công cụ, chạy MySQL, agent, test end-to-end | |

Kịch bản demo cho giảng viên: [docs/KICH_BAN_DEMO.md](docs/KICH_BAN_DEMO.md).

## Cài đặt lần đầu

```powershell
.\scripts\setup-tools.ps1      # Go, Node.js, MySQL bản portable vào %USERPROFILE%\tools (không cần quyền admin)
.\scripts\mysql.ps1 init       # tạo CSDL vault, user vault / vault_dev_pw
..\PasswordVault\scripts\build-applet.ps1
```

## Chạy hằng ngày

```powershell
.\scripts\start-dev.ps1 -Dev   # MySQL + server + agent, mỗi cái một cửa sổ
```

Mở http://127.0.0.1:8080, đăng nhập `admin` / `admin123` rồi đổi mật khẩu.
Simulator chỉ nhận **một** kết nối: khi dùng web, console APDU của Eclipse phải Disconnect.

Tắt: `.\scripts\stop-dev.ps1` (tắt server, agent, Vite, MySQL và đóng các cửa sổ start-dev đã mở).
Thêm `-KeepMySql` để giữ MySQL chạy, `-Simulators` để tắt luôn mọi simulator `jcsw.exe`.

## Kiểm thử

```powershell
..\PasswordVault\scripts\test-applet.ps1     # 303 test applet trên simulator
cd server; go test ./...                     # mật mã, challenge, đồng bộ thao tác chờ
.\scripts\e2e-test.ps1                       # 54 test end-to-end (server + agent -Dev + thẻ)
```

## Thiết kế bảo mật

- **adminKey riêng từng thẻ**: `HMAC-SHA256(khoá chủ, "VAULT-ADMIN-KEY" | cardId)[0..16]`. Khoá chủ nằm trong
  `server/data/secrets.json` (tự sinh lần đầu). **Mất file này thì không khoá / thu hồi trên thẻ được nữa - hãy sao lưu.**
- Agent không giữ bí mật nào: mỗi thao tác admin là một request, trong đó agent gửi ADMIN_CHALLENGE, nhờ server tính
  phản hồi (bằng token admin của người đang đăng nhập web), gửi ADMIN_AUTH rồi thực hiện lệnh - không có APDU nào chen giữa.
- Agent chỉ nghe `127.0.0.1` và từ chối request có `Origin` lạ, để trang web khác không điều khiển được thẻ.
- Challenge RSA do **server** sinh (32 byte, dùng 1 lần, hạn 2 phút) và server kiểm chữ ký bằng khoá công khai trong CSDL.
- Thao tác khi thẻ không cắm được ghi vào `pending_action`; lần sau thẻ kết nối, server từ chối thẻ và cấp token hạn chế
  (scope `pending`) chỉ đủ để app ghi thao tác đó lên thẻ.
- CSDL không chứa PIN, PUK hay mật khẩu két. Bản sao lưu là file VBK1 đã mã hoá trên thẻ.

## API chính

| Nhóm | Endpoint |
|---|---|
| Admin | `POST /api/admin/login`, `POST /api/admin/password`, `GET /api/stats`, `GET /api/logs` |
| Thẻ (admin) | `GET /api/cards`, `GET /api/cards/{id}`, `GET /api/cards/next-id`, `POST /api/cards`, `POST /api/cards/{id}/issue-key`, `/activate`, `/admin-response`, `/lock`, `/unlock`, `/revoke`, `DELETE /api/cards/{id}` (chỉ thẻ chờ kích hoạt) |
| Xác thực thẻ (công khai) | `POST /api/auth/challenge`, `POST /api/auth/verify` → token thẻ |
| App người dùng (token thẻ) | `POST /api/app/logs`, `POST /api/app/state`, `GET/POST /api/app/backups`, `GET /api/app/backups/{bid}` |
| Đồng bộ thao tác chờ | `POST /api/cards/{id}/pending/response`, `POST /api/cards/{id}/pending/done` |
| Card Agent | `GET /health`, `GET /card`, `POST /card/issue`, `POST /card/sign`, `POST /card/admin`, `POST /dev/blank-card` |

## Cấu hình server (biến môi trường hoặc `server/.env`)

`VAULT_ADDR` (mặc định `127.0.0.1:8080`), `VAULT_DB_DSN`, `VAULT_SECRETS_FILE`, `VAULT_WEB_DIR`,
`VAULT_ADMIN_USER` / `VAULT_ADMIN_PASSWORD` (chỉ dùng để tạo admin đầu tiên).

## Giới hạn hiện tại

- Chưa giới hạn số lần đăng nhập sai của admin (nên thêm rate limit khi triển khai thật).
- Server chạy HTTP; triển khai thật cần HTTPS (reverse proxy).
- Kho challenge nằm trong RAM: khởi động lại server thì challenge đang chờ mất (thẻ chỉ cần xin challenge mới).
