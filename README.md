# Quản lý mật khẩu bằng Smart Card

| Thư mục | Nội dung |
|---|---|
| [PasswordVault/](PasswordVault/) | Applet Java Card (project Eclipse) và bộ test chạy trên simulator |
| [vault-system/](vault-system/) | Vault server (Go), web quản trị (React), Card Agent (Java). Xem [vault-system/README.md](vault-system/README.md) |

Hai thư mục phải nằm cạnh nhau, vì Card Agent dùng lại `PasswordVault/tester/.../VaultCard.java`.

## Bắt đầu sau khi clone

1. Mở Eclipse, chọn **File → Import → Existing Projects into Workspace**, rồi trỏ tới thư mục `PasswordVault`.
2. Cài công cụ và CSDL: làm theo phần "Cài đặt lần đầu" trong [vault-system/README.md](vault-system/README.md).
3. `server/data/secrets.json` không có trên git. Server tự sinh file mới ở lần chạy đầu tiên.
