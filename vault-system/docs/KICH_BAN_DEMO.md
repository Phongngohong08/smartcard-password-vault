# Kịch bản demo – Hệ thống quản lý mật khẩu bằng Smart Card

Tài liệu này dùng khi trình bày với giảng viên. Mỗi mục gồm: **mục đích**, **thao tác**, **kết quả mong đợi**, và **giải thích khi được hỏi**. Tổng thời gian khoảng 25–30 phút.

Demo chạy trên Java Card Simulator. App Android chưa làm, nên các chức năng phía người dùng (PIN, két mật khẩu, PUK) được demo bằng console APDU của Eclipse. Hãy nói rõ điều này với giảng viên ngay từ đầu.

---

## Thứ tự demo

| # | Phần | Thời gian | Chứng minh điều gì |
|---|---|---|---|
| 1 | Kiến trúc hệ thống | 2 phút | Bí mật chỉ nằm trên thẻ |
| 2 | Đăng nhập web quản trị | 1 phút | Admin có tài khoản riêng, nhật ký ghi cả lần đăng nhập sai |
| 3 | Phát hành thẻ | 3 phút | Thẻ tự sinh khoá, server kiểm RSA trước khi kích hoạt |
| 4 | Chức năng người dùng trên thẻ (console) | 6 phút | PIN, két mật khẩu, tìm kiếm, sinh mật khẩu |
| 5 | Sai PIN 3 lần, mở bằng PUK | 3 phút | Bộ đếm lượt sai, Master Key không mất khi đổi PIN |
| 6 | Kiểm tra thẻ thật | 1 phút | Challenge–response RSA |
| 7 | Admin khoá / mở khoá trên thẻ | 3 phút | Thẻ tự từ chối khi bị khoá |
| 8 | Khoá khi thẻ không cắm | 2 phút | Thao tác chờ đồng bộ |
| 9 | Thẻ giả | 3 phút | Server phát hiện thẻ giả mạo mã thẻ |
| 10 | Thu hồi và phát hành thẻ thay thế | 3 phút | Thu hồi vĩnh viễn, thẻ mới nối với thẻ cũ |
| 11 | Tổng quan, nhật ký, CSDL | 3 phút | Theo dõi được mọi thao tác; CSDL không chứa bí mật |
| 12 | Kiểm thử tự động | 3 phút | 303 test applet, unit test, 54 test end-to-end |

Giá trị dùng xuyên suốt buổi demo (dùng đúng các giá trị này để lệnh console bên dưới chạy được):

| Mục | Giá trị |
|---|---|
| Thẻ thứ nhất | `SC000001`, chủ thẻ Nguyễn Văn An |
| PIN | `123456` |
| PUK | `12345678` (gõ tay, **không** bấm "Sinh ngẫu nhiên") |
| Tài khoản admin | `admin` / mật khẩu bạn đã đặt |

---

## 0. Chuẩn bị (làm trước buổi demo 15 phút)

1. **Eclipse**: Project → Clean để file CAP được build lại từ mã mới nhất.
2. **Bật simulator** trong Eclipse (Java Card Simulator, cổng 9025). Mở console APDU, chọn **Connect** rồi **Load, Install, Select** applet PasswordVault. Gõ `send 0x80 0x01 0x00 0x00 0x00;`, phải nhận `5641554C5420312E30` (chữ "VAULT 1.0"). Sau đó chọn **Disconnect**.
3. **Bật hệ thống** trong PowerShell:
   ```powershell
   cd C:\Users\Phong\eclipse-workspace\vault-system
   .\scripts\start-dev.ps1 -Dev
   ```
   Hai cửa sổ "Vault server :8080" và "Card Agent :8765" mở ra; cứ để chúng mở.
4. **Làm sạch CSDL** để thẻ đầu tiên có mã `SC000001`. Trong CSDL đang có thẻ test SC000001–SC000005 từ lúc phát triển. Chạy `.\scripts\mysql.ps1 shell`, rồi gõ:
   ```sql
   DELETE FROM backups; DELETE FROM audit_logs; DELETE FROM cards;
   exit
   ```
   Tài khoản admin vẫn được giữ.
5. **Bật simulator thứ hai** cho phần kiểm thử tự động (mục 12). Bộ test sẽ xoá thẻ trên simulator nó chạy, nên phải dùng simulator riêng:
   ```powershell
   Start-Process C:\javacard\simulator\runtime\bin\jcsw.exe -ArgumentList '-p=9026'
   ```
6. Mở http://127.0.0.1:8080, đăng nhập thử, rồi **đăng xuất** để lát nữa demo lại từ đầu.

> **Quy tắc vàng:** simulator chỉ nhận **một** kết nối một lúc. Trước khi bấm nút trên web, console Eclipse phải **Disconnect**. Trước khi gõ lệnh trong console, chọn **Connect** rồi `select 11223344550001;`. Trong lúc console đang Connect, góc trên web hiện "Đầu đọc đang bận" — điều này là bình thường.

---

## 1. Kiến trúc hệ thống

**Mục đích:** cho giảng viên thấy bức tranh chung trước khi đi vào chi tiết.

**Thao tác:** mở tài liệu triển khai, mục 1 (sơ đồ kiến trúc), rồi giới thiệu 4 thành phần:
- **Applet trên thẻ**: giữ PIN, PUK, Master Key, khoá riêng RSA và két mật khẩu đã mã hoá.
- **Vault server** (Go + MySQL): chỉ giữ khoá công khai, trạng thái thẻ, nhật ký và bản sao lưu đã mã hoá.
- **Card Agent** (Java): cầu nối trình duyệt ↔ thẻ, vì trình duyệt không nói chuyện trực tiếp được với thẻ.
- **Web quản trị** (React).

**Kết quả mong đợi:** giảng viên nắm được mọi phép mã hoá, giải mã và ký đều chạy trên thẻ.

**Khi được hỏi:**
- *"Sao cần agent?"* — Trình duyệt không truy cập được đầu đọc PC/SC, còn giao thức socket của simulator chỉ có thư viện Java. Agent không giữ bí mật nào; mọi khoá do server cấp theo từng lần, kèm token admin.

---

## 2. Đăng nhập web quản trị

**Mục đích:** admin có tài khoản riêng, mật khẩu băm bcrypt; người dùng thì không có tài khoản trên web.

**Thao tác:**
1. Đăng nhập bằng mật khẩu sai.
2. Đăng nhập lại bằng mật khẩu đúng.

**Kết quả mong đợi:**
- Lần sai: thông báo "Sai tên đăng nhập hoặc mật khẩu".
- Lần đúng: vào trang Tổng quan, số thẻ bằng 0. Mục "Hoạt động gần đây" đã có 2 dòng *Admin đăng nhập* (một thất bại, một thành công). Góc trên bên phải hiện "Thẻ trắng (chưa phát hành)" (đèn xanh).

**Khi được hỏi:**
- *"Lưu mật khẩu admin thế nào?"* — bcrypt trong bảng `admins`. Đăng nhập thành công nhận JWT hạn 8 giờ, lưu trong sessionStorage nên đóng tab là phải đăng nhập lại.

---

## 3. Phát hành thẻ

**Mục đích:** thẻ tự sinh Master Key và cặp khoá RSA-2048. Server chỉ kích hoạt thẻ sau khi đã kiểm tra được chữ ký của thẻ bằng khoá công khai vừa lưu.

**Thao tác:** vào **Phát hành thẻ**, điền:
- Mã thẻ: giữ `SC000001` (server gợi ý sẵn).
- Họ tên: `Nguyễn Văn An`; ngày sinh, email, SĐT tuỳ ý; có thể chọn ảnh đại diện.
- PIN `123456`, nhập lại PIN `123456`, PUK `12345678`.

Bấm **Phát hành thẻ** và chỉ cho giảng viên thấy 5 bước lần lượt chuyển sang dấu ✓.

**Kết quả mong đợi:**
- Cả 5 bước đều đạt. Bước 2 ghi thời gian sinh khoá RSA; bước 5 hiện dấu vân tay khoá công khai (dạng `EC:C7:94:…`).
- Màn hình hiện PUK `12345678` **một lần duy nhất**, kèm lời nhắc hệ thống không lưu PUK.
- Góc trên bên phải: "Thẻ SC000001 · Hoạt động".
- Bấm **Xem thẻ**: trạng thái *Hoạt động*; nhật ký có `Xác thực RSA – Kích hoạt thẻ` và `Phát hành thẻ`.

**Khi được hỏi:**
- *"Vì sao có trạng thái 'Chờ kích hoạt'?"* — Sau khi ghi thẻ, khoá công khai được lưu với trạng thái PENDING. Chỉ khi thẻ ký đúng một challenge mới của server thì mới chuyển ACTIVE. Như vậy khoá lưu trong CSDL chắc chắn khớp với thẻ.
- *"adminKey ghi vào thẻ lấy ở đâu?"* — Server dẫn xuất riêng cho từng thẻ: `HMAC-SHA256(khoá chủ, mã thẻ)`. Lộ khoá của một thẻ không ảnh hưởng thẻ khác.

---

## 4. Chức năng người dùng trên thẻ (console Eclipse)

**Mục đích:** chứng minh két mật khẩu nằm trên thẻ, được mã hoá, và chỉ mở được bằng PIN.

**Thao tác:** trong console Eclipse chọn **Connect**, rồi gõ lần lượt từng dòng:

| # | Lệnh | Ý nghĩa | Kết quả mong đợi |
|---|---|---|---|
| 1 | `select 11223344550001;` | Chọn applet | `SW:9000` |
| 2 | `send 0x80 0x11 0x00 0x00 0x00;` | GET_STATUS | `01 5343303030303031 03 05` (Hoạt động, SC000001, còn 3 lượt PIN, 5 lượt PUK) |
| 3 | `send 0x80 0x50 0x00 0x00 0x00;` | Xem két khi **chưa nhập PIN** | `SW:6982` (chưa xác thực) |
| 4 | `send 0x80 0x20 0x00 0x00 0x06 0x31 0x32 0x33 0x34 0x35 0x36;` | VERIFY_PIN `123456` | `SW:9000` |
| 5 | `send 0x80 0x41 0x00 0x00 0x00;` | Đọc hồ sơ (web đã ghi lúc phát hành) | Dữ liệu bắt đầu bằng `01` (tag họ tên), `SW:9000` |
| 6 | `send 0x80 0x51 0x00 0x00 0x0A 0x10 0x05 0x47 0x6D 0x61 0x69 0x6C 0x14 0x01 0x01 0x00;` | Thêm bản ghi "Gmail", nhóm email | `00` (ô số 0) |
| 7 | `send 0x80 0x53 0x00 0x00 0x08 0x61 0x62 0x63 0x31 0x32 0x33 0x34 0x35;` | Đặt mật khẩu `abc12345` cho ô 0 | `SW:9000` |
| 8 | `send 0x80 0x55 0x00 0x00 0x00;` | Đọc mật khẩu ô 0 | `6162633132333435` (`abc12345`) |
| 9 | `send 0x80 0x50 0x00 0x00 0x00;` | Danh sách ô | `01000000` (bit 0 = ô 0 có dữ liệu) |
| 10 | `send 0x80 0x57 0x00 0x00 0x02 0x67 0x6D 0x00;` | Tìm "gm" | `01000000` (tìm thấy Gmail, không phân biệt hoa thường) |
| 11 | `send 0x80 0x57 0x00 0x00 0x03 0x61 0x62 0x63 0x00;` | Tìm "abc" — chữ chỉ có trong **mật khẩu** | `00000000` (không thấy) |
| 12 | `send 0x80 0x58 0x10 0x0F 0x00;` | Sinh mật khẩu 16 ký tự, đủ 4 loại | 16 byte ngẫu nhiên, mỗi lần một khác |
| 13 | `send 0x80 0x23 0x00 0x00;` | LOGOUT | `SW:9000` |
| 14 | `send 0x80 0x55 0x00 0x00 0x00;` | Đọc mật khẩu sau khi đăng xuất | `SW:6982` |

Xong thì **Disconnect**.

**Khi được hỏi:**
- *"Dữ liệu trên thẻ có được mã hoá không?"* — Có. Mỗi ô két lưu `IV ‖ AES-CBC(MK, …)`, với IV ngẫu nhiên mới ở mỗi lần ghi. Phần thông tin và phần mật khẩu mã hoá riêng.
- *"Vì sao tìm 'abc' không thấy?"* — SEARCH chỉ giải mã phần thông tin (dịch vụ, URL, tên đăng nhập); phần mật khẩu không bao giờ bị giải mã trong lúc tìm.
- *"Sinh mật khẩu có ngẫu nhiên đều không?"* — Thẻ bỏ các byte r ≥ 256 − (256 mod n) nên không thiên lệch modulo. Bộ test đã sinh 1 600 chữ số, mỗi chữ số xuất hiện quanh 160 lần.

---

## 5. Sai PIN 3 lần và mở bằng PUK

**Mục đích:** thẻ tự đếm số lần sai, tự khoá. Mở bằng PUK thì đặt được PIN mới mà **không mất dữ liệu**, vì chỉ Master Key được bọc lại.

**Thao tác:** console **Connect**, `select 11223344550001;`, rồi gõ:

| # | Lệnh | Kết quả mong đợi |
|---|---|---|
| 1 | `send 0x80 0x20 0x00 0x00 0x06 0x30 0x30 0x30 0x30 0x30 0x30;` (PIN sai `000000`) | `63C2` (còn 2 lần) |
| 2 | Lặp lại lệnh trên | `63C1` |
| 3 | Lặp lại lệnh trên | `6983` (PIN đã bị khoá) |
| 4 | `send 0x80 0x11 0x00 0x00 0x00;` | `02 … 00 05` (trạng thái Khoá PIN, còn 0 lượt PIN) |
| 5 | `send 0x80 0x20 0x00 0x00 0x06 0x31 0x32 0x33 0x34 0x35 0x36;` (PIN **đúng**) | Vẫn `6983` — thẻ đã khoá thì PIN đúng cũng bị từ chối |
| 6 | `send 0x80 0x22 0x00 0x00 0x10 0x08 0x31 0x32 0x33 0x34 0x35 0x36 0x37 0x38 0x06 0x31 0x32 0x33 0x34 0x35 0x36;` (PUK `12345678`, PIN mới `123456`) | `SW:9000` |
| 7 | `send 0x80 0x11 0x00 0x00 0x00;` | `01 … 03 05` (Hoạt động trở lại) |
| 8 | `send 0x80 0x20 0x00 0x00 0x06 0x31 0x32 0x33 0x34 0x35 0x36;` | `SW:9000` |
| 9 | `send 0x80 0x55 0x00 0x00 0x00;` | Vẫn `6162633132333435` — mật khẩu `abc12345` còn nguyên |

Xong thì **Disconnect**.

**Khi được hỏi:**
- *"Rút thẻ ngay sau khi so sánh để không bị trừ lượt được không?"* — Không. Thẻ trừ bộ đếm **trước** khi so sánh, PIN đúng mới đặt lại về 3.
- *"Sai PUK 5 lần thì sao?"* — Thẻ chuyển sang Vô hiệu và xoá Master Key đã bọc, nên dữ liệu không giải mã được nữa. Không demo phần này trực tiếp vì không đảo ngược được; bộ test tự động có kiểm tra nó.

---

## 6. Kiểm tra thẻ thật

**Mục đích:** server xác thực thẻ bằng challenge–response RSA, không dựa vào mã thẻ.

**Thao tác:** trên web, vào **Thẻ → SC000001** (phải thấy "Thẻ này đang cắm"), rồi bấm **Kiểm tra thẻ thật/giả**.

**Kết quả mong đợi:** thông báo xanh "Thẻ thật: chữ ký khớp khoá công khai trong CSDL". Nhật ký thẻ có thêm `Xác thực RSA – Thành công`.

**Khi được hỏi:**
- *"Thẻ ký cái gì?"* — Thẻ ký `"VAULTAUTH" ‖ mã thẻ ‖ challenge 32 byte`. Challenge do server sinh, chỉ dùng một lần và hết hạn sau 2 phút, nên không phát lại được chữ ký cũ. Tiền tố cố định khiến thẻ không thể bị lợi dụng để ký dữ liệu tuỳ ý.

---

## 7. Admin khoá và mở khoá trên thẻ

**Mục đích:** khoá có hiệu lực **ngay trên thẻ**, không chỉ trong CSDL. Thao tác admin trên thẻ cần xác thực bằng khoá admin do server giữ.

**Thao tác:**
1. Trên trang thẻ SC000001 bấm **Khoá thẻ** → nhập lý do → **Khoá thẻ**.
2. Console **Connect**, `select 11223344550001;`, rồi gửi `send 0x80 0x20 0x00 0x00 0x06 0x31 0x32 0x33 0x34 0x35 0x36;` (PIN đúng). Sau đó **Disconnect**.
3. Trên web bấm **Mở khoá** → xác nhận.

**Kết quả mong đợi:**
- Bước 1: thông báo "đã thực hiện trên thẻ và cập nhật CSDL". Trạng thái *Bị khoá*; trên thẻ: *Khoá admin*.
- Bước 2: `SW:6985` — thẻ tự từ chối PIN đúng vì đang bị admin khoá.
- Bước 3: trạng thái quay về *Hoạt động*.

**Khi được hỏi:**
- *"Ai cũng gửi lệnh khoá được à?"* — Không. Agent gửi ADMIN_CHALLENGE, nhờ server tính `AES(adminKey của thẻ, challenge)` (cần token admin), gửi ADMIN_AUTH rồi mới khoá. Tất cả nằm trong một kết nối nên không lệnh nào chen vào giữa. Challenge dùng một lần.

---

## 8. Khoá khi thẻ không cắm

**Mục đích:** admin khoá được cả thẻ đang không ở trong tay (ví dụ người dùng báo mất). Server từ chối thẻ ngay, và thao tác sẽ được ghi lên thẻ ở lần kết nối sau.

**Thao tác:**
1. Vào **Phát hành thẻ** → bấm **Nạp thẻ trắng (simulator)**. Việc này giả lập rút thẻ SC000001 ra và cắm một thẻ trắng vào.
2. Vào **Thẻ → SC000001**: giờ hiện "Thẻ không cắm". Bấm **Khoá thẻ** → xác nhận.

**Kết quả mong đợi:**
- Thông báo vàng: "đã cập nhật CSDL. Chờ khoá trên thẻ - sẽ thực hiện khi thẻ kết nối lần sau".
- Thẻ có hai nhãn *Bị khoá* và *Chờ khoá trên thẻ*. Trang Tổng quan có cảnh báo "1 thẻ có thao tác admin chưa ghi lên thẻ".

**Khi được hỏi:**
- *"Lần sau thẻ cắm vào thì sao?"* — App xác thực RSA với server; server trả 403 kèm một token hạn chế (scope `pending`, 2 phút). Token này chỉ đủ để app xin phản hồi ADMIN_AUTH, ghi lệnh khoá lên thẻ rồi báo hoàn tất. Luồng này đã có test end-to-end; phần app sẽ làm trên Android.
- *"Khoá rồi mở lại trước khi thẻ kịp kết nối?"* — Hai thao tác tự triệt tiêu, nên thẻ không bị ghi vô ích.

---

## 9. Thẻ giả

**Mục đích:** biết mã thẻ thôi là không đủ. Thẻ giả mang **đúng mã SC000001** vẫn bị phát hiện, vì nó không có khoá riêng của thẻ thật.

**Thao tác:**
1. Thẻ đang cắm là thẻ trắng (từ mục 8). Console **Connect**, `select 11223344550001;`, rồi tự "phát hành" thẻ giả mang mã `SC000001`:
   ```
   send 0x80 0x10 0x00 0x00 0x28 0x53 0x43 0x30 0x30 0x30 0x30 0x30 0x31 0x06 0x31 0x32 0x33 0x34 0x35 0x36 0x08 0x31 0x32 0x33 0x34 0x35 0x36 0x37 0x38 0x00 0x01 0x02 0x03 0x04 0x05 0x06 0x07 0x08 0x09 0x0A 0x0B 0x0C 0x0D 0x0E 0x0F;
   ```
   Lệnh phải trả `SW:9000`. Sau đó **Disconnect**.
2. Web: **Thẻ → SC000001**. Trang hiện "Thẻ này đang cắm", vì agent chỉ nhìn mã thẻ.
3. Bấm **Kiểm tra thẻ thật/giả**. **Không** bấm Khoá hay Mở khoá ở bước này.

**Kết quả mong đợi:**
- Thông báo đỏ: "THẺ GIẢ: chữ ký không khớp khoá công khai đã lưu cho mã thẻ này".
- Trang Tổng quan: cảnh báo đỏ "1 lần xác thực RSA thất bại trong 24 giờ – có thể có thẻ giả"; ô *RSA thất bại* = 1.
- Nhật ký: `Xác thực RSA – Thất bại – Chữ ký không hợp lệ - nghi thẻ giả`.

**Khi được hỏi:**
- *"Kẻ gian làm thẻ giả có đọc được khoá riêng của thẻ thật không?"* — Không. Khoá riêng sinh trên thẻ và không có lệnh nào xuất nó ra; GET_PUBKEY chỉ trả modulus và số mũ công khai.

---

## 10. Thu hồi và phát hành thẻ thay thế

**Mục đích:** thu hồi là vĩnh viễn. Người dùng được cấp thẻ mới, nối với thẻ cũ để lấy lại bản sao lưu.

**Thao tác:**
1. **Phát hành thẻ → Nạp thẻ trắng (simulator)** để bỏ thẻ giả ra.
2. **Thẻ → SC000001 → Thu hồi**. Nhập lý do "Mất thẻ", gõ `SC000001` để xác nhận, rồi bấm **Thu hồi thẻ**.
3. **Phát hành thẻ**: mã gợi ý `SC000002`. Ở ô "Thay cho thẻ cũ" chọn `SC000001`, điền thông tin, PIN `123456`, PUK `12345678`, rồi phát hành.

**Kết quả mong đợi:**
- Bước 2: hộp xác nhận màu đỏ cảnh báo thao tác không đảo ngược được, nút chỉ bấm được khi đã gõ đúng mã thẻ. Sau khi thu hồi: *Đã thu hồi* và *Chờ thu hồi trên thẻ*.
- Bước 3: thẻ SC000002 *Hoạt động*. Trang chi tiết có dòng "Thay cho thẻ SC000001", và trang SC000001 có dòng "Đã thay bằng SC000002".

**Khi được hỏi:**
- *"Thu hồi trên thẻ làm gì?"* — Thẻ xoá Master Key đã bọc (cả bản bọc bằng PIN và bằng PUK) và chuyển sang Thu hồi, nên dữ liệu trên thẻ không giải mã được nữa. Mọi lệnh sau đó trả 6985.
- *"Khôi phục dữ liệu sang thẻ mới thế nào?"* — Thẻ mới đọc được bản sao lưu của thẻ cũ qua API. Applet giải mã bằng Master Key cũ (mở bằng passphrase) rồi mã hoá lại bằng Master Key của chính nó. Phần này demo bằng test tự động ở mục 12 vì app Android chưa làm.

---

## 11. Tổng quan, nhật ký, CSDL

**Mục đích:** admin theo dõi được mọi thao tác, và CSDL không chứa bí mật nào.

**Thao tác:**
1. Trang **Tổng quan**: chỉ cho thấy các ô số liệu, cảnh báo, biểu đồ 7 ngày (rê chuột lên cột để xem số), và danh sách hoạt động gần đây.
2. Trang **Nhật ký**: lọc *Mã thẻ* `SC000001`, sau đó lọc *Kết quả* = Thất bại.
3. Mở CSDL bằng `.\scripts\mysql.ps1 shell` trong PowerShell:
   ```sql
   SHOW COLUMNS FROM cards;
   SELECT card_id, owner_name, status, card_state, pending_action, HEX(LEFT(rsa_modulus, 8)) AS modulus_dau FROM cards;
   SELECT action, result, detail FROM audit_logs WHERE card_id = 'SC000001' ORDER BY id;
   exit
   ```

**Kết quả mong đợi:**
- Tổng quan: 2 thẻ, 1 hoạt động, 1 đã thu hồi, RSA thất bại = 1, cảnh báo 1 thẻ chờ đồng bộ.
- Nhật ký SC000001 có đủ chuỗi sự kiện: Xác thực RSA và Phát hành (mục 3) → Xác thực RSA (mục 6) → Khoá → Mở khoá (mục 7) → Khoá, chỉ CSDL (mục 8) → Xác thực RSA thất bại (mục 9) → Thu hồi (mục 10).
- Bảng `cards` **không có cột nào** chứa PIN, PUK hay Master Key, chỉ có khoá công khai (`rsa_modulus`, `rsa_exponent`).

**Khi được hỏi:**
- *"Admin có xem được mật khẩu của người dùng không?"* — Không. Két mã hoá bằng Master Key, và Master Key chỉ mở được bằng PIN hoặc PUK, mà cả hai chỉ nằm trên thẻ. Bản sao lưu trên server cũng đã mã hoá trên thẻ bằng passphrase của người dùng.

---

## 12. Kiểm thử tự động

**Mục đích:** mọi chức năng, kể cả các trường hợp lỗi và phần không demo tay được (sai PUK 5 lần, sao lưu/khôi phục, đồng bộ thao tác chờ), đều có test tự động.

**Thao tác:** trong PowerShell (simulator thứ hai cổng 9026 đã bật ở bước chuẩn bị):
```powershell
# 303 test applet - chạy trên simulator 9026, không ảnh hưởng thẻ demo
C:\Users\Phong\eclipse-workspace\PasswordVault\scripts\test-applet.ps1 -SimHost localhost:9026

# Unit test server
cd C:\Users\Phong\eclipse-workspace\vault-system\server; go test ./...
```

**Kết quả mong đợi:**
- Test applet in từng nhóm theo giai đoạn 1, 2, 3, 4, 6 và kết thúc bằng `==== KẾT QUẢ: 303 đạt, 0 lỗi ====`. Nên chỉ cho giảng viên vài dòng đáng chú ý: "Mở bằng PUK, đọc được hồ sơ cũ", "'secretword' chỉ có trong mật khẩu cũ -> không thấy", "Thẻ B có đúng các ô 0, 2, 3".
- `go test`: dòng `ok  vault/server`.

Test end-to-end (`.\scripts\e2e-test.ps1`, 54 test) cũng có, nhưng **đừng chạy trong buổi demo**: nó nạp thẻ trắng lên simulator 9025 và thêm thẻ test vào CSDL. Chỉ chạy trước, rồi kể lại kết quả.

**Khi được hỏi:**
- *"Test sao lưu làm thế nào khi chỉ có một simulator?"* — Test sao lưu ở thẻ A, nạp lại applet (thành thẻ B với Master Key khác), rồi khôi phục và so từng byte với dữ liệu của thẻ A.

---

## Câu hỏi thường gặp

| Câu hỏi | Trả lời ngắn |
|---|---|
| Đổi PIN có phải mã hoá lại cả két không? | Không. Dữ liệu mã hoá bằng Master Key; đổi PIN chỉ bọc lại 16 byte Master Key bằng khoá mới. |
| Mất điện giữa lúc ghi thì sao? | Ghi trong `beginTransaction`/`commitTransaction`: hoặc ghi hết, hoặc không ghi gì. Sinh khoá RSA làm ngoài transaction và thẻ vẫn "Chưa phát hành" cho tới khi commit. |
| PIN băm bằng gì? Có yếu điểm không? | SHA-256 với salt. Hạn chế: một vòng băm thì nhanh, nên nếu đọc trực tiếp được EEPROM có thể dò PIN ngắn. Hệ thống dựa vào chip an toàn và bộ đếm 3 lần sai. |
| Đường truyền thẻ ↔ máy có mã hoá không? | Chưa (chưa có secure messaging). Đây là hướng phát triển. |
| Mất file khoá của server thì sao? | Không còn khoá/thu hồi trên thẻ được các thẻ đã phát hành (vẫn chặn được trong CSDL). Vì vậy `server\data\secrets.json` phải sao lưu riêng. |
| So với thiết kế ban đầu đã đổi gì? | Thêm 6300 cho sai passphrase, phần đầu sao lưu 48 byte, adminKey riêng từng thẻ, SEARCH nhóm "khác" bằng P1 = 0x80, quy tắc ghi ảnh lần lượt. Danh sách đầy đủ ở mục 3.1 tài liệu triển khai. |
| Phần nào chưa làm? | App Android cho người dùng (cần thẻ Java Card thật có NFC), HTTPS, giới hạn đăng nhập sai của admin. |

---

## Khi có sự cố

| Hiện tượng | Nguyên nhân | Cách xử lý |
|---|---|---|
| Góc web hiện "Đầu đọc đang bận" | Console Eclipse đang Connect | Disconnect console |
| Góc web hiện "Card Agent chưa chạy" | Cửa sổ Card Agent bị đóng | Chạy lại `.\scripts\start-dev.ps1 -Dev` |
| Console gõ lệnh mà không có `[APDU-C]` | Thiếu từ khoá `send` ở đầu | Gõ `send 0x80 …;` |
| Console trả `6D00` cho mọi lệnh | Chưa chọn applet | `select 11223344550001;` |
| Phát hành báo "không phải thẻ trắng" | Thẻ trên simulator đã có dữ liệu | Bấm **Nạp thẻ trắng (simulator)** |
| `List` trong console báo `count: 0` | Simulator vừa khởi động lại, applet mất | Load, Install, Select lại, hoặc bấm Nạp thẻ trắng |
| Lệnh console ở mục 4 trả `6982` dù đã nhập PIN | Có lệnh từ web chen vào (web đã kết nối thẻ) nên phiên PIN mất | Gửi lại VERIFY_PIN rồi làm tiếp |
| Mã thẻ gợi ý không phải `SC000001` | Chưa làm sạch CSDL (bước 0.4) | Làm sạch CSDL, hoặc thay các byte `0x30 0x30 0x30 0x30 0x30 0x31` trong lệnh thẻ giả bằng mã thực tế |
