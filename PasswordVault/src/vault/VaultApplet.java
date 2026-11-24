package vault;

// ===================== IMPORT =====================
// javacard.framework : các lớp cơ bản - APDU (gói lệnh), Applet (lớp cha), ISO7816 (hằng số chuẩn),
//                      ISOException (trả mã lỗi SW), JCSystem (bộ nhớ RAM, transaction), Util (xử lý mảng).
// javacard.security  : khoá, băm (SHA-256), chữ ký (RSA), bộ sinh số ngẫu nhiên.
// javacardx.crypto   : Cipher (mã hoá/giải mã AES). Gói "x" = mở rộng, tuỳ chọn trên từng loại thẻ.
import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.AESKey;
import javacard.security.CryptoException;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.MessageDigest;
// RSAPublicKey: kiểu cụ thể của khoá công khai RSA, có getModulus()/getExponent()
// để lấy n và e gửi ra ngoài (dùng trong GET_PUBKEY).
import javacard.security.RSAPublicKey;
import javacard.security.RandomData;
import javacard.security.Signature;
import javacardx.crypto.Cipher;

/**
 * VaultApplet - Hệ thống quản lý mật khẩu cá nhân bằng Smart Card.
 *
 * Lệnh APDU (CLA = 0x80). "PIN" = phiên đã xác thực PIN và thẻ đang Hoạt động.
 *
 *  Phát hành, trạng thái
 *   0x01 GET_VERSION    -> "VAULT 1.0"
 *   0x10 ISSUE          cardId(8) | lenPIN | PIN | lenPUK | PUK | adminKey(16)
 *   0x11 GET_STATUS     -> state | cardId(8) | pinTriesLeft | pukTriesLeft
 *   0x12 GET_PUBKEY     P1 = 0, 1: nửa đầu / nửa sau modulus; P1 = 2: số mũ
 *  PIN, PUK, phiên
 *   0x20 VERIFY_PIN     PIN
 *   0x21 CHANGE_PIN     lenOld | PIN cũ | lenNew | PIN mới
 *   0x22 UNBLOCK_PUK    lenPUK | PUK | lenNew | PIN mới
 *   0x23 LOGOUT
 *  Xác thực thẻ bằng RSA
 *   0x30 INTERNAL_AUTH  challenge(32): ký "VAULTAUTH" | cardId | challenge
 *   0x31 GET_SIGNATURE  P1 = 0, 1: nửa đầu / nửa sau chữ ký
 *  Hồ sơ chủ thẻ (PIN)
 *   0x40 SET_PROFILE    TLV: 01 họ tên (≤64), 02 ngày sinh (10), 03 email (≤64), 04 SĐT (≤16)
 *   0x41 GET_PROFILE
 *   0x42 SET_AVATAR     P1 = khối (0-15), P2 = tổng số khối; ≤ 192 byte. Ghi lần lượt từ khối 0.
 *   0x43 GET_AVATAR     P1 = khối; P1 = 0xFF: hỏi số khối (0 = chưa có ảnh)
 *  Két mật khẩu (PIN, trừ GEN_PASSWORD)
 *   0x50 LIST_SLOTS     -> bitmap 4 byte (ô i: byte i/8, bit i%8)
 *   0x51 ADD_ENTRY      TLV: 10 dịch vụ (1-32, bắt buộc), 11 URL (≤64), 12 tên đăng nhập (≤48),
 *                            13 ghi chú (≤48), 14 nhóm (1 byte, 0-5)  -> số ô
 *   0x52 UPDATE_META    P1 = ô; TLV như trên
 *   0x53 SET_PASSWORD   P1 = ô; mật khẩu (1-64 byte)
 *   0x54 GET_META       P1 = ô
 *   0x55 GET_PASSWORD   P1 = ô
 *   0x56 DELETE_ENTRY   P1 = ô
 *   0x57 SEARCH         P1 = 0: mọi nhóm, 1-5: nhóm đó, 0x80: nhóm "khác" (0); từ khoá ≤ 32
 *   0x58 GEN_PASSWORD   P1 = độ dài 8-64; P2: bit0 thường, bit1 hoa, bit2 số, bit3 ký hiệu
 *  Sao lưu, khôi phục (PIN)
 *   0x60 BACKUP_BEGIN   passphrase (8-64 byte)
 *                       -> backupSalt(16) | AES(BK, MK)(16) | AES(MK, "VAULTBACKUPCHECK")(16)
 *                       với BK = SHA256(backupSalt | passphrase)[0..15]
 *   0x61 BACKUP_READ    P1 = ô; P2 = 0 thông tin, 1 mật khẩu -> blob đã mã hoá, giữ nguyên
 *   0x62 RESTORE_BEGIN  lenPass | passphrase | 48 byte phần đầu ở trên. Sai passphrase -> 6300
 *   0x63 RESTORE_WRITE  P1 = ô đích; P2 = 0 thông tin (tạo lại ô), 1 mật khẩu; dữ liệu = blob cũ.
 *                       Thẻ giải mã bằng MK cũ rồi mã hoá lại bằng MK của chính nó.
 *  Admin
 *   0x70 ADMIN_CHALLENGE -> challenge(16)
 *   0x71 ADMIN_AUTH      AES-128-CBC(adminKey, IV = 0, challenge); phải gửi NGAY sau 0x70
 *   0x72 ADMIN_LOCK      P1 = 1 khoá, P1 = 0 mở khoá
 *   0x73 REVOKE          thu hồi vĩnh viễn
 *
 * Trạng thái thẻ: 00 Chưa phát hành, 01 Hoạt động, 02 Khoá PIN, 03 Khoá admin, 04 Thu hồi, 05 Vô hiệu.
 *
 * =====================================================================
 * HƯỚNG DẪN ĐỌC (phần chú thích thêm để học)
 * =====================================================================
 * File dài, nên đọc theo thứ tự:
 *   1) 4 mục kiến thức nền ngay bên dưới (quan trọng nhất là mục 1 - kiến trúc khoá)
 *   2) Hằng số, field, constructor
 *   3) process(): nơi phân luồng lệnh theo INS
 *   4) Các lệnh theo GIAI ĐOẠN 1 -> 4 và phần MỞ RỘNG (sao lưu)
 *   5) Các hàm hỗ trợ ở cuối file (được gọi từ khắp nơi, gặp hàm nào lạ thì kéo xuống cuối xem)
 *
 * ---------------------------------------------------------------------
 * 1) KIẾN TRÚC KHOÁ (key hierarchy)
 * ---------------------------------------------------------------------
 *
 *     PIN --SHA256(pinKekSalt | PIN)[0..15]--> KEK_PIN --AES--> mkByPin  (EEPROM)
 *     PUK --SHA256(pukKekSalt | PUK)[0..15]--> KEK_PUK --AES--> mkByPuk  (EEPROM)
 *                                                                  |
 *                                       gỡ bọc khi VERIFY_PIN đúng  |
 *                                                                  v
 *                          MK (Master Key, 16 byte ngẫu nhiên, sinh 1 lần lúc ISSUE)
 *                          bản rõ CHỈ nằm trong RAM (sessionMk) trong suốt phiên
 *                                                                  |
 *                                         AES-128-CBC, IV ngẫu nhiên |
 *                                                                  v
 *                          hồ sơ, ảnh, thông tin + mật khẩu của 32 ô két (EEPROM)
 *
 *   - MK mã hoá MỌI dữ liệu người dùng.
 *   - MK KHÔNG BAO GIỜ nằm dạng rõ trong EEPROM, chỉ lưu bản đã "bọc" (wrap = mã hoá một khoá
 *     bằng một khoá khác). Đọc trộm được EEPROM mà không biết PIN/PUK cũng không có MK.
 *   - KEK (Key Encryption Key) không được lưu: mỗi lần cần thì tính lại từ PIN/PUK.
 *   - Đổi PIN: chỉ bọc lại MK bằng KEK mới (16 byte), không phải mã hoá lại cả két.
 *   - Quên PIN: dùng PUK gỡ bọc mkByPuk -> có lại MK -> đặt PIN mới. Dữ liệu không mất.
 *   - Thu hồi / vô hiệu thẻ: xoá mkByPin và mkByPuk -> không ai lấy lại được MK -> toàn bộ
 *     dữ liệu coi như đã bị xoá (crypto-erase) mà không cần xoá từng byte của két.
 *   - Kiểm tra PIN: thẻ lưu pinHash = SHA256(pinSalt | PIN) và so sánh HASH, không lưu PIN.
 *
 * ---------------------------------------------------------------------
 * 2) PHIÊN LÀM VIỆC (session)
 * ---------------------------------------------------------------------
 *   Các trạng thái "đã xác thực PIN", "đã xác thực admin", "có chữ ký chờ đọc"... là các BIT
 *   trong session[0] (RAM, CLEAR_ON_DESELECT). Cùng với sessionMk (khoá AES transient), chúng
 *   tự mất khi deselect / rút thẻ -> phiên mới luôn phải xác thực lại.
 *   Gom nhiều cờ vào 1 byte thay vì mỗi cờ một mảng boolean để tiết kiệm RAM.
 *   (Chỉ MẢNG mới tạo được dạng transient, nên kể cả 1 byte cũng phải là mảng 1 phần tử.)
 *
 * ---------------------------------------------------------------------
 * 3) VÒNG ĐỜI THẺ (field cardState, EEPROM)
 * ---------------------------------------------------------------------
 *   00 Chưa phát hành --ISSUE-----------------> 01 Hoạt động
 *   01 Hoạt động      --sai PIN 3 lần---------> 02 Khoá PIN
 *   02 Khoá PIN       --UNBLOCK_PUK đúng------> 01 Hoạt động
 *   01, 02            --sai PUK 5 lần---------> 05 Vô hiệu (vĩnh viễn, MK bị xoá)
 *   01 <-> 03         ADMIN_LOCK: P1 = 1 khoá, P1 = 0 mở (cần xác thực admin)
 *   01, 02, 03        --REVOKE (cần admin)----> 04 Thu hồi (vĩnh viễn, MK bị xoá)
 *
 * ---------------------------------------------------------------------
 * 4) ĐỊNH DẠNG DỮ LIỆU HAY GẶP
 * ---------------------------------------------------------------------
 *   - TLV (Tag-Length-Value): mỗi trường = [tag 1 byte][độ dài 1 byte][giá trị]. Xem checkTlv().
 *   - Blob mã hoá: [IV 16 byte][bản mã AES-CBC]. Xem encryptToWork() / decryptToScratch().
 *   - Dữ liệu 256 byte (modulus, chữ ký RSA) gửi làm 2 lần x 128 byte (P1 = 0, 1) cho vừa
 *     APDU ngắn, không phải dùng extended APDU (nhiều đầu đọc/simulator không hỗ trợ tốt).
 */
public class VaultApplet extends Applet {

    // ============================== Mã lệnh ==============================
    // CLA = 0x80: dải 0x80..0xFF là lệnh "proprietary" (riêng của ứng dụng), khác 0x00 là lệnh
    // chuẩn ISO (vd SELECT). process() từ chối mọi CLA khác 0x80 với lỗi 6E00.
    private static final byte CLA_VAULT = (byte) 0x80;

    // Mã INS chia nhóm theo chữ số hex hàng chục: 0x1_ phát hành, 0x2_ PIN/PUK, 0x3_ RSA,
    // 0x4_ hồ sơ, 0x5_ két, 0x6_ sao lưu, 0x7_ admin -> nhìn mã lệnh là biết thuộc nhóm nào.
    // (0x20 VERIFY trùng mã INS chuẩn ISO 7816 của lệnh VERIFY.)

    private static final byte INS_GET_VERSION     = (byte) 0x01;
    private static final byte INS_ISSUE           = (byte) 0x10;
    private static final byte INS_GET_STATUS      = (byte) 0x11;
    private static final byte INS_GET_PUBKEY      = (byte) 0x12;
    private static final byte INS_VERIFY_PIN      = (byte) 0x20;
    private static final byte INS_CHANGE_PIN      = (byte) 0x21;
    private static final byte INS_UNBLOCK_PUK     = (byte) 0x22;
    private static final byte INS_LOGOUT          = (byte) 0x23;
    private static final byte INS_INTERNAL_AUTH   = (byte) 0x30;
    private static final byte INS_GET_SIGNATURE   = (byte) 0x31;
    private static final byte INS_SET_PROFILE     = (byte) 0x40;
    private static final byte INS_GET_PROFILE     = (byte) 0x41;
    private static final byte INS_SET_AVATAR      = (byte) 0x42;
    private static final byte INS_GET_AVATAR      = (byte) 0x43;
    private static final byte INS_LIST_SLOTS      = (byte) 0x50;
    private static final byte INS_ADD_ENTRY       = (byte) 0x51;
    private static final byte INS_UPDATE_META     = (byte) 0x52;
    private static final byte INS_SET_PASSWORD    = (byte) 0x53;
    private static final byte INS_GET_META        = (byte) 0x54;
    private static final byte INS_GET_PASSWORD    = (byte) 0x55;
    private static final byte INS_DELETE_ENTRY    = (byte) 0x56;
    private static final byte INS_SEARCH          = (byte) 0x57;
    private static final byte INS_GEN_PASSWORD    = (byte) 0x58;
    private static final byte INS_BACKUP_BEGIN    = (byte) 0x60;
    private static final byte INS_BACKUP_READ     = (byte) 0x61;
    private static final byte INS_RESTORE_BEGIN   = (byte) 0x62;
    private static final byte INS_RESTORE_WRITE   = (byte) 0x63;
    private static final byte INS_ADMIN_CHALLENGE = (byte) 0x70;
    private static final byte INS_ADMIN_AUTH      = (byte) 0x71;
    private static final byte INS_ADMIN_LOCK      = (byte) 0x72;
    private static final byte INS_REVOKE          = (byte) 0x73;

    // ============================== Trạng thái thẻ ==============================
    // Giá trị của field cardState (EEPROM). Sơ đồ chuyển trạng thái: xem mục 3 ở đầu file.
    private static final byte STATE_UNISSUED     = (byte) 0x00;
    private static final byte STATE_ACTIVE       = (byte) 0x01;
    private static final byte STATE_PIN_BLOCKED  = (byte) 0x02;
    private static final byte STATE_ADMIN_LOCKED = (byte) 0x03;
    private static final byte STATE_REVOKED      = (byte) 0x04;
    private static final byte STATE_DISABLED     = (byte) 0x05;

    // ============================== Mã lỗi SW ==============================
    // Đặt tên mới cho dễ đọc; phần lớn chỉ là "bí danh" của hằng số có sẵn trong ISO7816
    // (cùng giá trị). Vd ISO7816.SW_FILE_INVALID = 0x6983, đúng bằng mã chuẩn
    // "authentication method blocked" nên được dùng lại làm SW_BLOCKED.
    //
    // Bảng tra nhanh các SW xuất hiện trong file:
    //   9000 thành công          6700 sai độ dài Lc        6982 chưa xác thực
    //   6983 bị khoá             6984 dữ liệu không hợp lệ  6985 sai trạng thái thẻ/phiên
    //   6A80 dữ liệu sai định dạng 6A84 két đầy            6A86 sai P1/P2
    //   6A88 không có dữ liệu    6300 sai passphrase        63Cx sai PIN/PUK, còn x lần
    //   6D00 INS không hỗ trợ    6E00 CLA không hỗ trợ      6F00 lỗi không xác định
    /** 63Cx: sai PIN/PUK, còn x lần (cộng x vào giá trị này). */
    private static final short SW_WRONG_CODE_BASE = (short) 0x63C0;
    /** 6983: PIN bị khoá, hoặc PUK hết lượt. */
    private static final short SW_BLOCKED = ISO7816.SW_FILE_INVALID;              // 6983
    /** 6982: chưa xác thực PIN / admin. */
    private static final short SW_NOT_AUTH = ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED; // 6982
    /** 6A84: két đã đầy. */
    private static final short SW_FULL = ISO7816.SW_FILE_FULL;                    // 6A84
    /** 6A88: ô trống / chưa có dữ liệu (hồ sơ, ảnh, mật khẩu). */
    private static final short SW_DATA_NOT_FOUND = (short) 0x6A88;
    /** 6300: xác minh thất bại (sai passphrase sao lưu). */
    private static final short SW_VERIFY_FAILED = (short) 0x6300;

    // ============================== Hằng số kích thước ==============================
    // Đơn vị: byte. Đặt tên cho mọi con số để code bên dưới dễ đọc và sửa một chỗ là đủ.
    //   CARD_ID_LEN    : mã thẻ 8 ký tự, vd "SC000001"
    //   SALT_LEN       : salt ngẫu nhiên trộn vào trước khi băm
    //   HASH_LEN       : đầu ra SHA-256
    //   KEY_LEN, IV_LEN: khoá và IV của AES-128 (= kích thước 1 khối AES)
    //   RSA_LEN        : modulus / chữ ký RSA-2048, HALF_RSA_LEN là một nửa để gửi 2 lần
    //   CHALLENGE_LEN  : challenge 32 byte máy chủ gửi để thẻ ký (INTERNAL_AUTH)
    //   ADMIN_CHAL_LEN : challenge 16 byte thẻ gửi cho admin (đúng 1 khối AES)
    private static final short CARD_ID_LEN   = 8;
    private static final short SALT_LEN      = 16;
    private static final short HASH_LEN      = 32;
    private static final short KEY_LEN       = 16;  // AES-128
    private static final short IV_LEN        = 16;
    private static final short RSA_LEN       = 256; // RSA-2048
    private static final short HALF_RSA_LEN  = 128;
    private static final short CHALLENGE_LEN = 32;
    private static final short ADMIN_CHAL_LEN = 16;

    // PIN: 6-12 ký tự in được; PUK: đúng 8 chữ số. Số lần thử: PIN 3 lần, PUK 5 lần.
    private static final byte PIN_MIN = 6;
    private static final byte PIN_MAX = 12;
    private static final byte PUK_LEN = 8;
    private static final byte PIN_TRIES_MAX = 3;
    private static final byte PUK_TRIES_MAX = 5;

    /** Một blob mã hoá: IV(16) | AES-CBC(≤ 208) */
    // Cách tính các giới hạn (padding luôn thêm ít nhất 1 byte rồi làm tròn lên bội số 16, xem pad()):
    //   - Thông tin ô dài nhất: (2+32)+(2+64)+(2+48)+(2+48)+(2+1) = 203 -> pad 208 -> blob 16+208 = 224
    //   - Một khối ảnh 192 byte                                  -> pad 208 -> blob 224
    //   - Hồ sơ dài nhất: (2+64)+(2+10)+(2+64)+(2+16) = 162       -> pad 176 -> blob 192 (< 224)
    //   - Mật khẩu 64 byte                                        -> pad 80  -> blob 96 (PW_BLOB_MAX)
    // => Mọi blob ≤ 224 byte, vừa trong APDU buffer.
    private static final short BLOB_MAX = 224;
    private static final short AVATAR_CHUNK_MAX = 192;
    private static final short AVATAR_MAX_CHUNKS = 16;

    // Két: 32 ô x 323 byte
    // Cả két là MỘT mảng byte dài 32 * 323 = 10336 byte (thay vì 32 đối tượng riêng - Java Card
    // tạo đối tượng tốn bộ nhớ quản lý). Ô thứ i bắt đầu tại i * SLOT_SIZE. Bố cục 1 ô:
    //
    //   offset: 0      1         2 ............. 225   226      227 ........ 322
    //           [flag] [metaLen] [ blob thông tin   ]  [pwLen]  [ blob mật khẩu ]
    //            1 B    1 B        224 B                1 B       96 B
    //
    //   flag = 0 trống, 1 có dữ liệu. metaLen / pwLen = độ dài thực của blob (0 = chưa có).
    //   Các hằng O_xxx dưới đây là offset của từng phần TRONG một ô.
    private static final short SLOTS = 32;
    private static final short SLOT_SIZE = 323;
    private static final short O_FLAG = 0;     // 1: 0 trống, 1 có dữ liệu
    private static final short O_META_LEN = 1; // 1
    private static final short O_META = 2;     // 224: IV | AES(TLV thông tin)
    private static final short O_PW_LEN = 226; // 1
    private static final short O_PW = 227;     // 96: IV | AES(mật khẩu)
    private static final short PW_MAX = 64;
    private static final short KEYWORD_MAX = 32;

    // Tag TLV của thông tin ô két: 10 dịch vụ, 11 URL, 12 tên đăng nhập, 13 ghi chú, 14 nhóm.
    // Chỉ khai báo những tag được code dùng tới (13 ghi chú không cần tìm kiếm nên không có hằng).
    // Nhóm: 1..5 do ứng dụng tự đặt tên, 0 = "khác" (không có tag nhóm cũng coi là 0).
    private static final byte TAG_SERVICE = (byte) 0x10;
    private static final byte TAG_URL = (byte) 0x11;
    private static final byte TAG_USERNAME = (byte) 0x12;
    private static final byte TAG_GROUP = (byte) 0x14;
    private static final byte GROUP_MAX = 5;
    private static final byte SEARCH_GROUP_OTHER = (byte) 0x80;

    // Giới hạn độ dài từng trường TLV (chỉ số = tag - tag đầu tiên)
    // Vd hồ sơ: tag 0x02 (ngày sinh) -> chỉ số 0x02 - 0x01 = 1 -> độ dài phải từ 10 tới 10.
    //    két : tag 0x12 (tên đăng nhập) -> chỉ số 0x12 - 0x10 = 2 -> độ dài 1..48.
    // Dùng bảng tra như vậy giúp checkTlv() viết một lần, dùng chung cho cả hồ sơ và két.
    private static final byte[] PROFILE_MIN = { 1, 10, 1, 1 };
    private static final byte[] PROFILE_MAX = { 64, 10, 64, 16 };
    private static final byte[] META_MIN = { 1, 1, 1, 1, 1 };
    private static final byte[] META_MAX = { 32, 64, 48, 48, 1 };

    // Dùng cho GEN_PASSWORD: 24 ký hiệu được phép, và số byte ngẫu nhiên lấy mỗi lần gọi RNG
    // (lấy theo lô 64 byte cho đỡ phải gọi RNG từng byte một - gọi RNG tốn thời gian).
    private static final byte[] SYMBOLS = { '!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '-', '_',
            '=', '+', '[', ']', '{', '}', ';', ':', ',', '.', '?', '/' };
    private static final short RND_BATCH = 64;

    // Sao lưu
    // PASS_MIN/MAX       : độ dài passphrase sao lưu
    // BACKUP_HEADER_LEN  : 48 = backupSalt(16) + MK đã bọc(16) + giá trị kiểm tra(16)
    // PW_BLOB_MAX        : blob mật khẩu tối đa (xem phần tính toán ở BLOB_MAX)
    private static final byte PASS_MIN = 8;
    private static final byte PASS_MAX = 64;
    private static final short BACKUP_HEADER_LEN = 48;
    private static final short PW_BLOB_MAX = 96;
    /** Hằng số 16 byte; AES(MK, hằng số) cho biết passphrase có gỡ ra đúng MK hay không. */
    private static final byte[] BACKUP_CHECK = { 'V', 'A', 'U', 'L', 'T', 'B', 'A', 'C', 'K', 'U', 'P',
            'C', 'H', 'E', 'C', 'K' };

    // Bit trong session[0]
    // Mỗi cờ là một bit riêng (giá trị 1, 2, 4, 8, 16, 32) nên có thể gom 6 cờ vào 1 byte.
    // Ba thao tác bit dùng khắp file:
    //   bật  : session[0] |= SES_PIN;              (OR  -> bit đó thành 1, các bit khác giữ nguyên)
    //   tắt  : session[0] &= (byte) ~SES_PIN;      (AND với phần bù -> bit đó thành 0)
    //   kiểm : (session[0] & SES_PIN) != 0          (khác 0 nghĩa là bit đang bật)
    private static final byte SES_PIN = (byte) 0x01;   // đã xác thực PIN
    private static final byte SES_ADMIN = (byte) 0x02; // đã xác thực admin
    private static final byte SES_SIG = (byte) 0x04;   // có chữ ký RSA chờ đọc
    private static final byte SES_CHAL = (byte) 0x08;  // vừa gửi admin challenge
    private static final byte SES_BACKUP = (byte) 0x10;  // đã BACKUP_BEGIN
    private static final byte SES_RESTORE = (byte) 0x20; // đã RESTORE_BEGIN, MK cũ nằm trong restoreMk

    private static final byte[] VERSION = { 'V', 'A', 'U', 'L', 'T', ' ', '1', '.', '0' };
    // Tiền tố thẻ tự thêm vào trước challenge khi ký (xem internalAuth)
    private static final byte[] AUTH_PREFIX = { 'V', 'A', 'U', 'L', 'T', 'A', 'U', 'T', 'H' };

    // ============================== Persistent (EEPROM) ==============================
    // Field của applet (và mọi thứ tạo bằng new) nằm trong EEPROM: rút thẻ, mất điện vẫn còn.
    // Ngược lại, RAM (transient) bị xoá khi deselect / rút thẻ - xem phần Transient bên dưới.
    // "final" với mảng: biến luôn trỏ tới 1 mảng duy nhất tạo trong constructor; nội dung vẫn sửa được.
    // Biến đơn (cardState, pinTriesLeft...) không final vì giá trị phải thay đổi.

    // Trạng thái vòng đời (00..05) và mã thẻ 8 ký tự
    private byte cardState;
    private final byte[] cardId;

    // Bộ thông tin của PIN:
    //   pinSalt     : salt để tính pinHash
    //   pinHash     : SHA256(pinSalt | PIN) - dùng để kiểm tra PIN đúng/sai
    //   pinKekSalt  : salt KHÁC để tính KEK_PIN = SHA256(pinKekSalt | PIN)[0..15]
    //   pinTriesLeft: số lần còn được thử (đếm NGƯỢC từ 3). Phải nằm trong EEPROM: nếu để RAM thì
    //                 rút thẻ cắm lại là bộ đếm về đầu -> thử PIN vô hạn lần.
    // Salt ngẫu nhiên giúp: 2 thẻ cùng PIN "123456" vẫn có hash khác nhau, và không tra được
    // bảng hash tính sẵn (rainbow table).
    private final byte[] pinSalt;
    private final byte[] pinHash;
    private final byte[] pinKekSalt;
    private byte pinTriesLeft;

    // Bộ thông tin của PUK (mã mở khoá), ý nghĩa giống hệt PIN
    private final byte[] pukSalt;
    private final byte[] pukHash;
    private final byte[] pukKekSalt;
    private byte pukTriesLeft;

    /** Master Key bọc bằng KEK dẫn xuất từ PIN / từ PUK. */
    private final byte[] mkByPin;
    private final byte[] mkByPuk;

    // adminKey  : khoá AES 16 byte chung giữa thẻ và máy chủ quản trị, nạp lúc ISSUE.
    //             Admin chứng minh mình biết khoá này qua challenge-response (0x70, 0x71).
    // rsaKeyPair: cặp khoá RSA-2048 sinh NGAY TRÊN THẺ lúc ISSUE. Khoá bí mật không bao giờ ra
    //             khỏi thẻ; khoá công khai gửi cho máy chủ để kiểm tra chữ ký (INTERNAL_AUTH).
    private final AESKey adminKey;
    private final KeyPair rsaKeyPair;

    /** Hồ sơ: độ dài blob (0 = chưa có) + IV | AES(TLV). */
    private byte profileLen;
    private final byte[] profileBlob;

    /** Ảnh: 16 khối, mỗi khối IV | AES(≤ 192 byte). */
    // avatarBlob: 16 x 224 byte, khối i bắt đầu tại i * BLOB_MAX. avatarLens[i] = độ dài blob khối i.
    // Ảnh dài tối đa 16 x 192 = 3072 byte (vd ảnh JPEG nhỏ 64x64). Phải chia khối vì 1 APDU
    // chỉ chở được tối đa 255 byte dữ liệu.
    private final byte[] avatarBlob;
    private final byte[] avatarLens;
    private byte avatarChunks; // số khối đã ghi
    private byte avatarTotal;  // tổng số khối của ảnh đang ghi

    /** Két mật khẩu: 32 ô x 323 byte. */
    private final byte[] vault;

    // ============================== Transient (RAM, mất khi deselect) ==============================
    // Tất cả là CLEAR_ON_DESELECT: tự xoá về 0 khi chọn applet khác hoặc rút thẻ.
    // RAM trên thẻ rất ít (thường 1-4 KB) nên chỉ có vài bộ đệm, dùng đi dùng lại cho mọi lệnh.
    //   session : 1 byte chứa các cờ SES_xxx của phiên
    //   sigBuf  : giữ chữ ký RSA 256 byte giữa INTERNAL_AUTH và 2 lần GET_SIGNATURE
    //   scratch : bộ đệm nháp đa năng (bản rõ, hash, MK tạm...). Luôn được xoá sau khi dùng
    //             (clearScratch) để dữ liệu nhạy cảm không nằm lại trong RAM.
    private final byte[] session;
    private final byte[] sigBuf;
    private final byte[] scratch;
    /** Bộ đệm ra của phép mã hoá (IV | ciphertext), và bitmap/charset tạm. */
    private final byte[] work;
    private final byte[] adminChallenge;
    // adminChallenge: challenge 16 byte vừa gửi cho admin, chờ so với câu trả lời ở 0x71.
    // 3 khoá AES dưới đây có kiểu TYPE_AES_TRANSIENT_DESELECT: giá trị khoá nằm trong RAM và tự
    // bị xoá khi deselect. Đây là cách duy nhất để có "khoá tạm" (không thể đặt AESKey vào mảng
    // transient như với byte).
    /** Master Key đã mở khoá, chỉ tồn tại trong phiên. */
    private final AESKey sessionMk;
    /** Khoá tạm để bọc / gỡ bọc MK bằng KEK. */
    private final AESKey kekKey;
    /** Master Key của thẻ cũ khi khôi phục. */
    private final AESKey restoreMk;

    // ============================== Đối tượng mật mã ==============================
    // Tạo 1 lần trong constructor bằng getInstance() (không dùng new), dùng chung cho mọi lệnh.
    // Thuật toán chạy bằng bộ đồng xử lý mật mã của thẻ, applet chỉ gọi API.
    //   rng: số ngẫu nhiên | sha256: băm 32 byte | aesCbc: AES-128 chế độ CBC, không tự đệm (NOPAD)
    //   rsaSigner: ký RSA kèm SHA-256 (thẻ tự băm dữ liệu rồi ký, chuẩn PKCS#1)
    // Chỉ có MỘT aesCbc: mỗi lần dùng gọi init() lại với khoá + chế độ + IV phù hợp.
    private final RandomData rng;
    private final MessageDigest sha256;
    private final Cipher aesCbc;
    private final Signature rsaSigner;

    // Bố cục scratch dùng trong ISSUE / CHANGE_PIN / UNBLOCK_PUK.
    //
    //   0      16        32           48         80         96        112          128        160        176      208
    //   [ MK ][pinSalt][pinKekSalt][ pinHash  ][mkByPin][pukSalt][pukKekSalt][ pukHash  ][mkByPuk][  TMP  ]
    //
    // Lý do tính trước vào RAM: các bước tính toán (băm, AES, sinh ngẫu nhiên) khá lâu và có thể
    // lỗi giữa chừng. Tính xong hết trong RAM rồi mới chép sang EEPROM trong 1 transaction ngắn
    // -> EEPROM chỉ có 2 khả năng: toàn bộ giá trị cũ, hoặc toàn bộ giá trị mới.
    // Các phép tính ghi vào scratch trước, rồi mới chép sang EEPROM trong một transaction.
    private static final short S_MK          = 0;   // 16  Master Key rõ
    private static final short S_PIN_SALT    = 16;  // 16
    private static final short S_PIN_KEKSALT = 32;  // 16
    private static final short S_PIN_HASH    = 48;  // 32
    private static final short S_MK_BY_PIN   = 80;  // 16
    private static final short S_PUK_SALT    = 96;  // 16
    private static final short S_PUK_KEKSALT = 112; // 16
    private static final short S_PUK_HASH    = 128; // 32
    private static final short S_MK_BY_PUK   = 160; // 16
    private static final short S_TMP         = 176; // 32  hash / KEK tạm
    private static final short BUF_LEN       = 256;

    /**
     * Constructor: chạy 1 lần khi cài applet. Cấp phát TOÀN BỘ bộ nhớ cần dùng ở đây
     * (đa số thẻ không có garbage collector: "new" trong process() sẽ tốn thêm EEPROM mỗi lệnh
     *  và không bao giờ được thu hồi).
     */
    private VaultApplet() {
        // ---- Mảng persistent (EEPROM), tổng khoảng 14 KB ----
        cardId = new byte[CARD_ID_LEN];
        pinSalt = new byte[SALT_LEN];
        pinHash = new byte[HASH_LEN];
        pinKekSalt = new byte[SALT_LEN];
        pukSalt = new byte[SALT_LEN];
        pukHash = new byte[HASH_LEN];
        pukKekSalt = new byte[SALT_LEN];
        mkByPin = new byte[KEY_LEN];
        mkByPuk = new byte[KEY_LEN];
        profileBlob = new byte[BLOB_MAX];
        avatarBlob = new byte[(short) (AVATAR_MAX_CHUNKS * BLOB_MAX)];
        avatarLens = new byte[AVATAR_MAX_CHUNKS];
        // 10336 byte - mảng lớn nhất. Vẫn < 32767 nên độ dài vừa kiểu short.
        vault = new byte[(short) (SLOTS * SLOT_SIZE)];
        // Mới cài xong: chưa phát hành. Phải gửi ISSUE thì thẻ mới dùng được.
        cardState = STATE_UNISSUED;

        // Khoá persistent: mới tạo "vỏ", chưa có giá trị. adminKey nạp ở ISSUE (setKey),
        // rsaKeyPair sinh ở ISSUE (genKeyPair).
        // KeyBuilder.buildKey(keyType, keyLength, keyEncryption): tạo một đối tượng khoá rỗng
        //   keyType       : loại khoá + nơi lưu. TYPE_AES = khoá AES lưu trong EEPROM (persistent)
        //   keyLength     : độ dài khoá tính bằng BIT (LENGTH_AES_128 = 128 bit = 16 byte)
        //   keyEncryption : false = không yêu cầu thẻ mã hoá giá trị khoá khi nạp vào (hầu như luôn false)
        // Trả về kiểu chung Key -> phải ép sang AESKey để gọi được setKey/getKey.
        adminKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
        // new KeyPair(algorithm, keyLength): "vỏ" chứa 1 cặp khoá công khai + bí mật, chưa có giá trị.
        //   ALG_RSA_CRT : RSA với khoá bí mật dạng CRT (5 thành phần p, q, ...) - ký nhanh hơn ~4 lần
        //   LENGTH_RSA_2048 : modulus 2048 bit = 256 byte
        rsaKeyPair = new KeyPair(KeyPair.ALG_RSA_CRT, KeyBuilder.LENGTH_RSA_2048);

        // ---- Bộ nhớ transient (RAM), tổng khoảng 800 byte ----
        // Chỉ TẠO mảng CLEAR_ON_DESELECT ở đây, không đọc/ghi (applet chưa được chọn).
        // (Mảng CLEAR_ON_DESELECT chỉ được truy cập khi applet đang được chọn, nếu không sẽ ném
        //  SecurityException. Trong lúc cài đặt, applet chưa hề được chọn.)
        // JCSystem.makeTransientByteArray(length, event): tạo mảng byte trong RAM
        //   length : số byte
        //   event  : khi nào mảng tự bị xoá về 0. CLEAR_ON_DESELECT = khi applet bị bỏ chọn
        //            (chọn applet khác, rút thẻ); CLEAR_ON_RESET = chỉ khi thẻ mất điện / reset
        // Biến (session, scratch...) vẫn là field persistent, chỉ NỘI DUNG mảng là nằm trong RAM.
        session = JCSystem.makeTransientByteArray((short) 1, JCSystem.CLEAR_ON_DESELECT);
        sigBuf = JCSystem.makeTransientByteArray(RSA_LEN, JCSystem.CLEAR_ON_DESELECT);
        scratch = JCSystem.makeTransientByteArray(BUF_LEN, JCSystem.CLEAR_ON_DESELECT);
        work = JCSystem.makeTransientByteArray(BUF_LEN, JCSystem.CLEAR_ON_DESELECT);
        adminChallenge = JCSystem.makeTransientByteArray(ADMIN_CHAL_LEN, JCSystem.CLEAR_ON_DESELECT);
        // Giống adminKey ở trên, chỉ khác keyType: TYPE_AES_TRANSIENT_DESELECT = giá trị khoá nằm
        // trong RAM và tự bị xoá khi deselect.
        sessionMk = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_DESELECT,
                KeyBuilder.LENGTH_AES_128, false);
        kekKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_DESELECT,
                KeyBuilder.LENGTH_AES_128, false);
        restoreMk = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_DESELECT,
                KeyBuilder.LENGTH_AES_128, false);

        // ---- Đối tượng mật mã ----
        // RNG: thử ALG_KEYGENERATION (Java Card 3.0.5+, đủ tốt để sinh khoá) trước; thẻ cũ không có
        // thì lùi về ALG_SECURE_RANDOM (loại cũ, vẫn an toàn mật mã).
        // Dùng biến cục bộ r vì rng là final: Java chỉ cho gán biến final ĐÚNG 1 LẦN, không gán
        // được ở cả try lẫn catch. Gán vào r trước, xong mới gán rng = r một lần duy nhất.
        // RandomData.getInstance(algorithm): lấy bộ sinh số ngẫu nhiên của thẻ theo thuật toán.
        // Không dùng "new RandomData()" được: các lớp mật mã đều là lớp trừu tượng, thẻ tự cung cấp
        // bản cài đặt qua getInstance.
        RandomData r;
        try {
            r = RandomData.getInstance(RandomData.ALG_KEYGENERATION);
        } catch (CryptoException e) {
            r = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
        }
        rng = r;
        // Thuật toán không có trên thẻ -> getInstance ném CryptoException. Ở đây cố ý KHÔNG bắt
        // exception đó. Applet bắt buộc phải có đủ các thuật toán
        // này; thẻ nào thiếu thì exception làm việc cài đặt thất bại luôn - báo lỗi sớm lúc cài
        // còn hơn cài được rồi mới hỏng lúc dùng.
        // Xxx.getInstance(algorithm, externalAccess):
        //   algorithm      : thuật toán cụ thể (SHA-256 / AES-128-CBC không padding / RSA + SHA-256 PKCS#1)
        //   externalAccess : false = chỉ applet này dùng đối tượng, không chia sẻ cho applet khác
        sha256 = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
        aesCbc = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
        rsaSigner = Signature.getInstance(Signature.ALG_RSA_SHA_256_PKCS1, false);
    }

    // install(): JCRE gọi 1 lần duy nhất khi cài applet. Tạo đối tượng (chạy constructor ở trên) rồi
    // register() để đăng ký với thẻ bằng AID lấy từ bArray: bArray[bOffset] = độ dài AID, AID nằm ngay sau.
    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new VaultApplet().register(bArray, (short) (bOffset + 1), bArray[bOffset]);
    }

    /**
     * Được gọi cho MỖI lệnh APDU. Chỉ làm 3 việc chung rồi chuyển sang hàm xử lý riêng của từng lệnh.
     * Mỗi hàm xử lý tự kiểm tra điều kiện của nó (requirePin, requireAdmin...).
     */
    public void process(APDU apdu) {
        // SELECT: không làm gì. Lúc này mọi dữ liệu CLEAR_ON_DESELECT đã về 0 -> phiên mới trống.
        if (selectingApplet()) {
            return;
        }
        // apdu.getBuffer(): trả về bộ đệm APDU - mảng byte (thường 261 byte, trong RAM) do JCRE quản lý.
        // Lúc này nó đã có 5 byte header: buf[0..4] = CLA INS P1 P2 Lc. Phần data chưa có, phải
        // gọi setIncomingAndReceive (xem receive()) mới nhận về buf[5..]. Dữ liệu trả lời cũng
        // được ghi vào chính mảng này rồi gửi đi bằng setOutgoingAndSend.
        byte[] buf = apdu.getBuffer();
        // Việc chung 1: chỉ nhận lệnh có CLA = 0x80 (buf[0])
        // ISOException.throwIt(sw): dừng xử lý ngay và trả về mã trạng thái sw (2 byte, vd 6E00)
        // thay cho 9000. Giống "throw", code phía sau không chạy nữa.
        if (buf[ISO7816.OFFSET_CLA] != CLA_VAULT) {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }
        byte ins = buf[ISO7816.OFFSET_INS];

        // Việc chung 2: huỷ cờ SES_CHAL nếu lệnh hiện tại không phải ADMIN_AUTH.
        // Admin challenge chỉ dùng được cho lệnh NGAY SAU nó.
        // -> challenge "sống" đúng 1 lệnh: kẻ gian không thể lấy challenge rồi từ từ tìm câu trả lời
        //    trong khi xen các lệnh khác vào.
        if (ins != INS_ADMIN_AUTH) {
            session[0] &= (byte) ~SES_CHAL;
        }

        // Việc chung 3: chuyển tới hàm xử lý theo INS.
        // Mỗi case gọi hàm rồi "return" luôn (thay cho break) - viết gọn trên 1 dòng.
        // GET_META và GET_PASSWORD dùng chung 1 hàm getSlotBlob, chỉ khác offset phần dữ liệu trong ô.
        switch (ins) {
        case INS_GET_VERSION:
            // Util.arrayCopyNonAtomic(src, srcOff, dest, destOff, length): tham số giống hệt
            // Util.arrayCopy (xem ISSUE), chỉ khác là KHÔNG nguyên tử / không tham gia transaction.
            // Đổi lại nó nhanh hơn và không tốn bộ đệm transaction -> dùng khi đích là RAM (buf,
            // scratch...) vì RAM đằng nào cũng mất khi mất điện. Ghi vào EEPROM thì dùng arrayCopy.
            Util.arrayCopyNonAtomic(VERSION, (short) 0, buf, (short) 0, (short) VERSION.length);
            // apdu.setOutgoingAndSend(bOff, len): gửi len byte trong bộ đệm APDU, bắt đầu từ
            // buf[bOff], làm dữ liệu trả lời. Thẻ tự thêm 9000 phía sau khi process() kết thúc.
            apdu.setOutgoingAndSend((short) 0, (short) VERSION.length);
            return;
        case INS_ISSUE:           issue(apdu); return;
        case INS_GET_STATUS:      getStatus(apdu); return;
        case INS_GET_PUBKEY:      getPubKey(apdu); return;
        case INS_VERIFY_PIN:      verifyPin(apdu); return;
        case INS_CHANGE_PIN:      changePin(apdu); return;
        case INS_UNBLOCK_PUK:     unblockPuk(apdu); return;
        case INS_LOGOUT:          clearSession(); return;
        case INS_INTERNAL_AUTH:   internalAuth(apdu); return;
        case INS_GET_SIGNATURE:   getSignature(apdu); return;
        case INS_SET_PROFILE:     setProfile(apdu); return;
        case INS_GET_PROFILE:     getProfile(apdu); return;
        case INS_SET_AVATAR:      setAvatar(apdu); return;
        case INS_GET_AVATAR:      getAvatar(apdu); return;
        case INS_LIST_SLOTS:      listSlots(apdu); return;
        case INS_ADD_ENTRY:       addEntry(apdu); return;
        case INS_UPDATE_META:     updateMeta(apdu); return;
        case INS_SET_PASSWORD:    setPassword(apdu); return;
        case INS_GET_META:        getSlotBlob(apdu, O_META_LEN, O_META); return;
        case INS_GET_PASSWORD:    getSlotBlob(apdu, O_PW_LEN, O_PW); return;
        case INS_DELETE_ENTRY:    deleteEntry(apdu); return;
        case INS_SEARCH:          search(apdu); return;
        case INS_GEN_PASSWORD:    genPassword(apdu); return;
        case INS_BACKUP_BEGIN:    backupBegin(apdu); return;
        case INS_BACKUP_READ:     backupRead(apdu); return;
        case INS_RESTORE_BEGIN:   restoreBegin(apdu); return;
        case INS_RESTORE_WRITE:   restoreWrite(apdu); return;
        case INS_ADMIN_CHALLENGE: adminChallenge(apdu); return;
        case INS_ADMIN_AUTH:      adminAuth(apdu); return;
        case INS_ADMIN_LOCK:      adminLock(apdu); return;
        case INS_REVOKE:          revoke(); return;
        default:
            ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    // =====================================================================
    // GIAI ĐOẠN 1 - Phát hành, PIN/PUK, RSA
    // =====================================================================

    /**
     * 0x10 ISSUE - phát hành thẻ: nạp mã thẻ, PIN, PUK, khoá admin; sinh RSA và Master Key.
     * Chỉ làm được 1 lần (khi thẻ đang "Chưa phát hành").
     *
     * Ví dụ data (40 byte): "SC000001" | 06 "123456" | 08 "12345678" | 16 byte adminKey
     *   53 43 30 30 30 30 30 31  06 31 32 33 34 35 36  08 31 32 33 34 35 36 37 38  [16 byte]
     */
    private void issue(APDU apdu) {
        if (cardState != STATE_UNISSUED) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        byte[] buf = apdu.getBuffer();
        short lc = receive(apdu);
        // off = "con trỏ đọc", chạy dần từ đầu dữ liệu (buf[5]); end = vị trí ngay sau byte cuối.
        // Kỹ thuật đọc tuần tự này dùng cho mọi lệnh có nhiều trường độ dài thay đổi.
        short off = ISO7816.OFFSET_CDATA;
        short end = (short) (off + lc);

        // ---- Tách và kiểm tra dữ liệu: cardId(8) | lenPIN | PIN | lenPUK | PUK | adminKey(16)
        // Mỗi trường chỉ ghi lại VỊ TRÍ (xxOff) và độ dài, không chép đi đâu - tiết kiệm RAM.
        // cardId: 8 byte cố định
        short cardIdOff = off;
        // "off += x" không cần ép (short) vì toán tử gộp += tự ép kiểu; còn "off = off + x" thì phải ép.
        off += CARD_ID_LEN;
        // Phải còn ít nhất 1 byte (byte độ dài PIN) -> off phải < end
        if (off >= end) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        // Đọc byte độ dài PIN (không dấu) rồi tăng off qua byte đó (off++ hậu tố)
        short pinLen = (short) (buf[off++] & 0xFF);
        short pinOff = off;
        off += pinLen;
        // Sau PIN phải còn byte độ dài PUK
        if (off >= end) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        short pukLen = (short) (buf[off++] & 0xFF);
        short pukOff = off;
        off += pukLen;
        // adminKey: 16 byte cố định ở cuối
        short adminKeyOff = off;
        off += KEY_LEN;
        // Đọc xong phải đúng tới cuối dữ liệu, thừa hay thiếu đều là sai định dạng
        if (off != end) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        // Độ dài đã đúng -> kiểm tra nội dung từng trường (sai thì 6A80)
        checkCardId(buf, cardIdOff);
        checkPinFormat(buf, pinOff, pinLen);
        checkPukFormat(buf, pukOff, pukLen);

        // ---- Các bước chậm / sinh ngẫu nhiên: làm NGOÀI transaction.
        // Nếu mất nguồn ở đây, thẻ vẫn ở "Chưa phát hành" nên ISSUE làm lại được.
        // (Bộ đệm transaction có dung lượng giới hạn - JCSystem.getMaxCommitCapacity() - nên không
        //  nhét việc sinh khoá RSA, vốn ghi nhiều dữ liệu và rất lâu, vào transaction.)

        // Sinh cặp khoá RSA-2048 ngay trên thẻ (chậm, có thể vài giây)
        // genKeyPair(): không tham số, không trả về gì - kết quả ghi luôn vào 2 khoá bên trong
        // rsaKeyPair, lấy ra bằng getPublic() / getPrivate(). Khoá bí mật không bao giờ rời thẻ.
        rsaKeyPair.genKeyPair();
        // Nạp khoá admin: 16 byte bắt đầu tại buf[adminKeyOff]
        // key.setKey(keyData, kOff): chép giá trị khoá từ keyData[kOff..] vào đối tượng khoá.
        //   Không có tham số độ dài: hàm tự đọc đúng số byte của khoá (AES-128 -> 16 byte).
        //   Sau lệnh này key.isInitialized() = true, dùng được cho Cipher.
        adminKey.setKey(buf, adminKeyOff);

        // Sinh Master Key ngẫu nhiên 16 byte vào scratch[S_MK]
        // rng.nextBytes(buffer, offset, length): ghi length byte ngẫu nhiên vào buffer[offset..offset+length)
        rng.nextBytes(scratch, S_MK, KEY_LEN);
        // Từ PIN: sinh salt, tính hash và bọc MK -> kết quả ghi vào các vùng S_PIN_xxx của scratch
        deriveCredential(buf, pinOff, pinLen, S_PIN_SALT, S_PIN_KEKSALT, S_PIN_HASH, S_MK_BY_PIN);
        // Từ PUK: tương tự, ghi vào các vùng S_PUK_xxx. Hai bản bọc mkByPin, mkByPuk chứa CÙNG một MK.
        deriveCredential(buf, pukOff, pukLen, S_PUK_SALT, S_PUK_KEKSALT, S_PUK_HASH, S_MK_BY_PUK);

        // ---- Ghi tất cả vào EEPROM trong một transaction
        // TRANSACTION: mọi lệnh ghi EEPROM giữa beginTransaction() và commitTransaction() hoặc là
        // cùng thành công, hoặc (nếu mất điện / lỗi giữa chừng) cùng bị huỷ, trả về giá trị cũ.
        // Không có transaction mà rút thẻ giữa chừng thì có thể ra thẻ "nửa vời": đã có PIN mới
        // nhưng chưa có PUK, hoặc state = Hoạt động mà salt vẫn toàn 0...
        // Lưu ý: chỉ Util.arrayCopy và phép gán field/phần tử mảng mới tham gia transaction;
        // các hàm *NonAtomic thì KHÔNG (xem wipeKeysAndSetState).
        JCSystem.beginTransaction();
        Util.arrayCopy(buf, cardIdOff, cardId, (short) 0, CARD_ID_LEN);
        storePinCredential();
        // Util.arrayCopy(src, srcOff, dest, destOff, length): chép length byte
        //   từ src[srcOff .. srcOff+length) sang dest[destOff .. destOff+length)
        //   src, srcOff   : mảng nguồn và vị trí bắt đầu đọc
        //   dest, destOff : mảng đích và vị trí bắt đầu ghi
        //   length        : số byte cần chép
        // Ví dụ dòng ngay dưới: chép 16 byte (SALT_LEN) từ scratch[96..111] (S_PUK_SALT = 96, RAM)
        // sang pukSalt[0..15] (EEPROM). Các dòng tiếp theo cũng y như vậy, chỉ khác vùng
        // nguồn trong scratch, mảng đích và độ dài.
        // (Hàm trả về destOff + length, tức vị trí ngay sau byte cuối vừa ghi - ở đây không dùng.)
        Util.arrayCopy(scratch, S_PUK_SALT, pukSalt, (short) 0, SALT_LEN);
        Util.arrayCopy(scratch, S_PUK_KEKSALT, pukKekSalt, (short) 0, SALT_LEN);
        Util.arrayCopy(scratch, S_PUK_HASH, pukHash, (short) 0, HASH_LEN);
        Util.arrayCopy(scratch, S_MK_BY_PUK, mkByPuk, (short) 0, KEY_LEN);
        pinTriesLeft = PIN_TRIES_MAX;
        pukTriesLeft = PUK_TRIES_MAX;
        // Đổi trạng thái sau cùng: thẻ chỉ "Hoạt động" khi mọi thứ ở trên đã ghi xong
        cardState = STATE_ACTIVE;
        JCSystem.commitTransaction();

        // Xoá MK rõ và mọi giá trị tạm khỏi RAM. Lưu ý: ISSUE KHÔNG mở phiên, phải VERIFY_PIN sau đó.
        clearScratch();
    }

    /**
     * 0x11 GET_STATUS - không cần PIN, ai cũng đọc được (ứng dụng cần biết trạng thái để hiển thị
     * màn hình phù hợp: phát hành, nhập PIN, nhập PUK...). Không lộ gì bí mật.
     * Trả về 11 byte: [0] state | [1..8] cardId | [9] số lần thử PIN còn lại | [10] số lần thử PUK còn lại
     */
    private void getStatus(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        buf[0] = cardState;
        Util.arrayCopyNonAtomic(cardId, (short) 0, buf, (short) 1, CARD_ID_LEN);
        buf[9] = pinTriesLeft;
        buf[10] = pukTriesLeft;
        apdu.setOutgoingAndSend((short) 0, (short) 11);
    }

    /**
     * 0x12 GET_PUBKEY - lấy khoá công khai RSA (n, e) để máy chủ lưu lại, dùng kiểm tra chữ ký sau này.
     * Khoá công khai không bí mật nên không cần PIN.
     *   P1 = 0: 128 byte đầu của modulus n | P1 = 1: 128 byte sau | P1 = 2: số mũ e
     */
    private void getPubKey(APDU apdu) {
        if (cardState == STATE_UNISSUED) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        byte[] buf = apdu.getBuffer();
        // getPublic() trả về kiểu chung PublicKey -> ép sang RSAPublicKey để gọi getModulus/getExponent
        RSAPublicKey pub = (RSAPublicKey) rsaKeyPair.getPublic();
        byte p1 = buf[ISO7816.OFFSET_P1];
        short len;
        if (p1 == 0 || p1 == 1) {
            // Lấy cả modulus 256 byte vào scratch, rồi chỉ chép nửa cần gửi (từ 0 hoặc từ 128) sang buf
            // getModulus(buffer, offset): ghi modulus n vào buffer[offset..], trả về số byte đã ghi (256).
            // getExponent bên dưới cũng cùng kiểu tham số.
            pub.getModulus(scratch, (short) 0);
            Util.arrayCopyNonAtomic(scratch, (short) (p1 == 0 ? 0 : HALF_RSA_LEN), buf, (short) 0, HALF_RSA_LEN);
            len = HALF_RSA_LEN;
        } else if (p1 == 2) {
            // Ghi e thẳng vào buf, trả về số byte. Thường e = 65537 = 01 00 01 (3 byte).
            len = pub.getExponent(buf, (short) 0);
        } else {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
            return;
        }
        apdu.setOutgoingAndSend((short) 0, len);
    }

    /**
     * 0x20 VERIFY_PIN - xác thực PIN và MỞ PHIÊN: đúng PIN thì gỡ bọc MK vào sessionMk (RAM).
     * Từ đó các lệnh cần PIN mới giải mã / mã hoá được dữ liệu.
     * Ví dụ: 80 20 00 00 06 31 32 33 34 35 36 ("123456") -> 9000 | sai -> 63C2, 63C1 | khoá -> 6983
     */
    private void verifyPin(APDU apdu) {
        // Thẻ phải đang Hoạt động (Khoá PIN -> 6983, trạng thái khác -> 6985)
        requirePinUsable();
        byte[] buf = apdu.getBuffer();
        short lc = receive(apdu);
        // Kiểm tra định dạng TRƯỚC khi đụng tới bộ đếm: gửi nhầm dữ liệu rác (sai độ dài,
        // ký tự lạ) thì báo 6A80 mà không bị trừ lượt thử.
        checkPinFormat(buf, ISO7816.OFFSET_CDATA, lc);

        // Huỷ phiên cũ trước khi thử: VERIFY sai thì phiên đang mở (nếu có) cũng bị đóng
        session[0] &= (byte) ~SES_PIN;
        // key.clearKey(): xoá giá trị khoá (ghi đè 0), sau đó isInitialized() = false và mọi
        // Cipher.init với khoá này sẽ ném CryptoException -> không ai dùng được MK cũ nữa.
        sessionMk.clearKey();

        // So PIN với hash đã lưu. Sai -> hàm này ném 63Cx / 6983 và verifyPin dừng tại đây.
        checkPinOrThrow(buf, ISO7816.OFFSET_CDATA, lc);

        // PIN đúng: mở Master Key vào sessionMk
        // unwrapMk tính KEK từ PIN rồi giải mã mkByPin -> MK rõ nằm ở scratch[S_MK]
        unwrapMk(buf, ISO7816.OFFSET_CDATA, lc, pinKekSalt, mkByPin);
        // Nạp MK vào khoá transient sessionMk (tự mất khi deselect)
        sessionMk.setKey(scratch, S_MK);
        // Bật cờ "đã xác thực PIN"
        session[0] |= SES_PIN;
        // Xoá bản MK rõ trong scratch - từ giờ MK chỉ còn nằm trong đối tượng sessionMk
        clearScratch();
    }

    /**
     * 0x21 CHANGE_PIN - đổi PIN (cần biết PIN cũ). Dữ liệu két KHÔNG phải mã hoá lại vì vẫn dùng MK cũ,
     * chỉ có bản bọc mkByPin được làm lại với KEK tính từ PIN mới.
     */
    private void changePin(APDU apdu) {
        requirePinUsable();
        byte[] buf = apdu.getBuffer();
        short lc = receive(apdu);
        short end = (short) (ISO7816.OFFSET_CDATA + lc);

        // lenOld | PIN cũ | lenNew | PIN mới
        // Đọc tuần tự giống ISSUE. Điều kiện cuối "off + newPinLen == end": PIN mới phải kết thúc
        // đúng ở cuối dữ liệu.
        short off = ISO7816.OFFSET_CDATA;
        short oldPinLen = (short) (buf[off++] & 0xFF);
        short oldPinOff = off;
        off += oldPinLen;
        if (off >= end) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        short newPinLen = (short) (buf[off++] & 0xFF);
        short newPinOff = off;
        if ((short) (off + newPinLen) != end) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        checkPinFormat(buf, oldPinOff, oldPinLen);
        checkPinFormat(buf, newPinOff, newPinLen);

        // PIN cũ phải đúng (sai thì cũng bị trừ lượt như VERIFY_PIN)
        checkPinOrThrow(buf, oldPinOff, oldPinLen);

        // Gỡ bọc MK bằng KEK cũ, rồi bọc lại bằng KEK mới (salt mới).
        // unwrapMk -> scratch[S_MK] = MK; deriveCredential dùng chính scratch[S_MK] để bọc lại.
        // Dữ liệu két mã hoá bằng MK nên không phải đụng tới.
        unwrapMk(buf, oldPinOff, oldPinLen, pinKekSalt, mkByPin);
        deriveCredential(buf, newPinOff, newPinLen, S_PIN_SALT, S_PIN_KEKSALT, S_PIN_HASH, S_MK_BY_PIN);

        // Ghi 4 giá trị (salt, kekSalt, hash, bản bọc) của PIN mới cùng lúc trong transaction:
        // nếu chỉ ghi được hash mới mà bản bọc vẫn cũ, PIN mới "đúng" nhưng không mở được MK.
        JCSystem.beginTransaction();
        storePinCredential();
        JCSystem.commitTransaction();

        // PIN cũ vừa đúng nên coi như phiên đã xác thực
        sessionMk.setKey(scratch, S_MK);
        session[0] |= SES_PIN;
        clearScratch();
    }

    /**
     * 0x22 UNBLOCK_PUK - quên PIN / PIN bị khoá: dùng PUK để đặt PIN mới mà KHÔNG mất dữ liệu
     * (vì mkByPuk cũng chứa cùng MK). Dùng được khi thẻ Hoạt động hoặc Khoá PIN.
     * Sai PUK 5 lần -> thẻ Vô hiệu vĩnh viễn, MK bị xoá.
     */
    private void unblockPuk(APDU apdu) {
        if (cardState != STATE_ACTIVE && cardState != STATE_PIN_BLOCKED) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        byte[] buf = apdu.getBuffer();
        short lc = receive(apdu);
        short end = (short) (ISO7816.OFFSET_CDATA + lc);

        // lenPUK | PUK | lenNew | PIN mới
        short off = ISO7816.OFFSET_CDATA;
        short pukLen = (short) (buf[off++] & 0xFF);
        short pukOff = off;
        off += pukLen;
        if (off >= end) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        short newPinLen = (short) (buf[off++] & 0xFF);
        short newPinOff = off;
        if ((short) (off + newPinLen) != end) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        checkPukFormat(buf, pukOff, pukLen);
        checkPinFormat(buf, newPinOff, newPinLen);

        // Đóng mọi phiên đang mở: dùng PUK là thao tác "khôi phục", không tin phiên cũ nữa
        clearSession();

        // Kiểm tra PUK - giảm bộ đếm TRƯỚC khi so sánh (chống rút thẻ giữa chừng)
        // ("Tearing": kẻ gian rút thẻ ngay khi biết so sánh sai để bộ đếm chưa kịp ghi. Trừ trước,
        //  đúng thì mới đặt lại, nên lượt thử luôn bị tính. Xem thêm checkPinOrThrow.)
        // Không dùng chung checkPinOrThrow vì PUK hết lượt thì xử lý khác: vô hiệu thẻ.
        if (pukTriesLeft == 0) {
            wipeKeysAndSetState(STATE_DISABLED);
            ISOException.throwIt(SW_BLOCKED);
        }
        // Ghi 1 byte field persistent là nguyên tử (atomic) dù không có transaction
        pukTriesLeft--;
        // Tính SHA256(pukSalt | PUK nhập vào) vào scratch[S_TMP], rồi so với pukHash đã lưu
        // Util.arrayCompare(src, srcOff, dest, destOff, length): so sánh từng byte của
        //   src[srcOff..srcOff+length) với dest[destOff..destOff+length)
        //   trả về 0 nếu giống hệt; -1 / 1 nếu khác (đoạn src nhỏ hơn / lớn hơn) -> "!= 0" là khác.
        hashWithSalt(pukSalt, buf, pukOff, pukLen, scratch, S_TMP);
        if (Util.arrayCompare(scratch, S_TMP, pukHash, (short) 0, HASH_LEN) != 0) {
            clearScratch();
            if (pukTriesLeft == 0) {
                wipeKeysAndSetState(STATE_DISABLED);
                ISOException.throwIt(SW_BLOCKED);
            }
            ISOException.throwIt((short) (SW_WRONG_CODE_BASE | pukTriesLeft));
        }

        // PUK đúng: mở MK bằng KEK của PUK, đặt PIN mới
        // Sau 2 dòng dưới: scratch[S_MK] = MK, các vùng S_PIN_xxx = bộ thông tin của PIN mới.
        // Transaction phía sau ghi PIN mới + đặt lại cả 2 bộ đếm + đưa thẻ về Hoạt động, cùng lúc.
        unwrapMk(buf, pukOff, pukLen, pukKekSalt, mkByPuk);
        deriveCredential(buf, newPinOff, newPinLen, S_PIN_SALT, S_PIN_KEKSALT, S_PIN_HASH, S_MK_BY_PIN);

        JCSystem.beginTransaction();
        storePinCredential();
        pinTriesLeft = PIN_TRIES_MAX;
        pukTriesLeft = PUK_TRIES_MAX;
        cardState = STATE_ACTIVE;
        JCSystem.commitTransaction();

        clearScratch();
        // Người dùng phải VERIFY_PIN bằng PIN mới để mở phiên.
    }

    /**
     * 0x30 INTERNAL_AUTH - thẻ chứng minh "tôi đúng là thẻ thật" bằng chữ ký RSA (challenge-response):
     *   1. Máy chủ sinh challenge ngẫu nhiên 32 byte, gửi cho thẻ.
     *   2. Thẻ ký "VAULTAUTH" | cardId | challenge bằng khoá bí mật RSA (chỉ thẻ thật mới có).
     *   3. Máy chủ đọc chữ ký (GET_SIGNATURE x 2), tự dựng lại đúng thông điệp đó và kiểm tra bằng
     *      khoá công khai đã lưu lúc phát hành. Đúng -> thẻ thật.
     * Challenge mới mỗi lần nên chữ ký cũ ghi lén được cũng không dùng lại được (chống replay).
     * Không cần PIN: xác thực THẺ, không phải xác thực NGƯỜI.
     */
    private void internalAuth(APDU apdu) {
        requireIssuedAlive();
        byte[] buf = apdu.getBuffer();
        short lc = receive(apdu);
        if (lc != CHALLENGE_LEN) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        // Huỷ chữ ký cũ (nếu có) trước khi tạo chữ ký mới
        session[0] &= (byte) ~SES_SIG;

        // Thông điệp được ký: "VAULTAUTH"(9) | cardId(8) | challenge(32)
        // Thẻ tự thêm tiền tố nên không thể bị lợi dụng để ký dữ liệu tuỳ ý.
        // (Nếu thẻ ký nguyên văn bất cứ thứ gì được gửi vào, kẻ gian có thể đưa một văn bản khác
        //  cho thẻ ký và dùng chữ ký đó vào việc khác. Có tiền tố cố định + cardId thì chữ ký chỉ
        //  có nghĩa là "thẻ cardId trả lời challenge này".)
        // Ghép thông điệp vào scratch: arrayCopyNonAtomic trả về (vị trí đích + số byte đã chép), tức
        // vị trí ngay sau đoạn vừa chép -> dùng luôn làm điểm bắt đầu của đoạn tiếp theo.
        short off = Util.arrayCopyNonAtomic(AUTH_PREFIX, (short) 0, scratch, (short) 0, (short) AUTH_PREFIX.length);
        off = Util.arrayCopyNonAtomic(cardId, (short) 0, scratch, off, CARD_ID_LEN);
        off = Util.arrayCopyNonAtomic(buf, ISO7816.OFFSET_CDATA, scratch, off, CHALLENGE_LEN);

        // Ký off = 49 byte trong scratch (thẻ tự băm SHA-256 rồi ký), chữ ký 256 byte ghi vào sigBuf.
        // Chữ ký quá dài để gửi trong 1 lần nên giữ trong sigBuf (RAM), máy chủ đọc bằng GET_SIGNATURE.
        // rsaSigner.init(key, mode): chọn khoá và chế độ. MODE_SIGN + khoá BÍ MẬT để ký
        //   (bên kiểm tra sẽ dùng MODE_VERIFY + khoá công khai).
        // rsaSigner.sign(inBuff, inOffset, inLength, sigBuff, sigOffset):
        //   băm SHA-256 inBuff[inOffset..inOffset+inLength), ký, ghi chữ ký vào sigBuff[sigOffset..]
        //   và trả về độ dài chữ ký (256 byte với RSA-2048).
        rsaSigner.init(rsaKeyPair.getPrivate(), Signature.MODE_SIGN);
        rsaSigner.sign(scratch, (short) 0, off, sigBuf, (short) 0);
        session[0] |= SES_SIG;
        clearScratch();
    }

    /**
     * 0x31 GET_SIGNATURE - đọc chữ ký vừa tạo ở INTERNAL_AUTH, mỗi lần 128 byte (P1 = 0 rồi P1 = 1).
     * Chỉ đọc được khi cờ SES_SIG đang bật (đã có INTERNAL_AUTH trong phiên này).
     */
    private void getSignature(APDU apdu) {
        if ((session[0] & SES_SIG) == 0) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        byte[] buf = apdu.getBuffer();
        byte p1 = buf[ISO7816.OFFSET_P1];
        if (p1 != 0 && p1 != 1) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
        Util.arrayCopyNonAtomic(sigBuf, (short) (p1 == 0 ? 0 : HALF_RSA_LEN), buf, (short) 0, HALF_RSA_LEN);
        apdu.setOutgoingAndSend((short) 0, HALF_RSA_LEN);
    }

    // =====================================================================
    // GIAI ĐOẠN 2 - Hồ sơ và ảnh
    // =====================================================================

    /**
     * 0x40 SET_PROFILE - lưu hồ sơ chủ thẻ (dạng TLV), mã hoá bằng MK. Ghi đè hồ sơ cũ.
     * Ví dụ data: 01 03 "Lan" | 02 0A "01/02/2003"
     *           = 01 03 4C 61 6E  02 0A 30 31 2F 30 32 2F 32 30 30 33
     */
    private void setProfile(APDU apdu) {
        requirePin();
        byte[] buf = apdu.getBuffer();
        short lc = receive(apdu);
        if (lc == 0) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        // Kiểm tra TLV hợp lệ (tag 01..04, không trùng, độ dài đúng giới hạn) TRƯỚC khi lưu
        checkTlv(buf, ISO7816.OFFSET_CDATA, lc, (byte) 0x01, PROFILE_MIN, PROFILE_MAX);

        // Mã hoá: work[0..n) = IV | bản mã
        short n = encryptToWork(buf, ISO7816.OFFSET_CDATA, lc);
        // Ghi blob + độ dài cùng lúc: tránh trường hợp blob mới mà độ dài cũ (giải mã ra rác)
        JCSystem.beginTransaction();
        Util.arrayCopy(work, (short) 0, profileBlob, (short) 0, n);
        profileLen = (byte) n;
        JCSystem.commitTransaction();
    }

    /**
     * 0x41 GET_PROFILE - giải mã hồ sơ và trả về TLV rõ.
     * Lưu ý: dữ liệu trả về ở dạng rõ trên đường truyền thẻ <-> đầu đọc. Hệ thống thương mại
     * thường thêm kênh bảo mật (secure channel, vd GlobalPlatform SCP03) để mã hoá cả đường truyền.
     */
    private void getProfile(APDU apdu) {
        requirePin();
        if (profileLen == 0) {
            ISOException.throwIt(SW_DATA_NOT_FOUND);
        }
        // profileLen là byte có dấu (blob 192 byte = 0xC0 sẽ đọc ra -64) -> & 0xFF để ra 192
        short n = decryptToScratch(profileBlob, (short) 0, (short) (profileLen & 0xFF));
        // Bản rõ đang ở scratch[0..n): chép ra buf, xoá scratch, gửi đi
        sendScratch(apdu, n);
    }

    /**
     * 0x42 SET_AVATAR: P1 = khối, P2 = tổng số khối. Khối 0 bắt đầu một ảnh mới.
     *
     * Ảnh lớn hơn 1 APDU nên gửi nhiều lần. Ví dụ ảnh 500 byte -> 3 khối (192 + 192 + 116):
     *   80 42 00 03 C0 [192 byte]    khối 0 / 3
     *   80 42 01 03 C0 [192 byte]    khối 1 / 3
     *   80 42 02 03 74 [116 byte]    khối 2 / 3  -> từ đây ảnh "hoàn chỉnh"
     * Mỗi khối được mã hoá riêng (IV riêng) và lưu ở ô riêng trong avatarBlob.
     */
    private void setAvatar(APDU apdu) {
        requirePin();
        byte[] buf = apdu.getBuffer();
        short idx = (short) (buf[ISO7816.OFFSET_P1] & 0xFF);
        short total = (short) (buf[ISO7816.OFFSET_P2] & 0xFF);
        if (total == 0 || total > AVATAR_MAX_CHUNKS || idx >= total) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
        short lc = receive(apdu);
        if (lc == 0 || lc > AVATAR_CHUNK_MAX) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        // avatarChunks = số khối đã ghi liên tiếp từ 0; avatarTotal = tổng số khối dự kiến.
        // Ảnh hoàn chỉnh khi avatarChunks == avatarTotal.
        if (idx == 0) {
            // Ảnh mới: đánh dấu chưa có khối nào trước, nên ảnh cũ không còn hợp lệ
            // (2 lệnh gán này cố ý nằm NGOÀI transaction: dù khối 0 ghi lỗi, ảnh cũ cũng đã bị
            //  huỷ, không bao giờ ra ảnh lai nửa cũ nửa mới.)
            avatarChunks = 0;
            avatarTotal = (byte) total;
        } else if (idx != avatarChunks || total != avatarTotal) {
            // Phải ghi lần lượt 0, 1, 2... với cùng tổng số khối
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        short n = encryptToWork(buf, ISO7816.OFFSET_CDATA, lc);
        // Ghi khối idx vào vị trí idx * 224, cập nhật độ dài và số khối đã ghi trong 1 transaction
        JCSystem.beginTransaction();
        Util.arrayCopy(work, (short) 0, avatarBlob, (short) (idx * BLOB_MAX), n);
        avatarLens[idx] = (byte) n;
        avatarChunks = (byte) (idx + 1);
        JCSystem.commitTransaction();
    }

    /**
     * 0x43 GET_AVATAR: P1 = khối; P1 = 0xFF trả về số khối (0 nếu chưa có ảnh hoàn chỉnh).
     * Cách đọc: gửi P1 = FF để biết số khối k, rồi đọc P1 = 0, 1, ..., k-1 và nối lại.
     */
    private void getAvatar(APDU apdu) {
        requirePin();
        byte[] buf = apdu.getBuffer();
        short idx = (short) (buf[ISO7816.OFFSET_P1] & 0xFF);
        // Chỉ trả ảnh khi đã ghi đủ mọi khối (đang gửi dở ảnh mới thì coi như chưa có ảnh)
        boolean complete = avatarChunks != 0 && avatarChunks == avatarTotal;
        if (idx == 0xFF) {
            buf[0] = complete ? avatarChunks : 0;
            apdu.setOutgoingAndSend((short) 0, (short) 1);
            return;
        }
        if (idx >= AVATAR_MAX_CHUNKS) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
        if (!complete || idx >= avatarChunks) {
            ISOException.throwIt(SW_DATA_NOT_FOUND);
        }
        short n = decryptToScratch(avatarBlob, (short) (idx * BLOB_MAX), (short) (avatarLens[idx] & 0xFF));
        sendScratch(apdu, n);
    }

    // =====================================================================
    // GIAI ĐOẠN 3 - Két mật khẩu
    // =====================================================================

    /**
     * 0x50 LIST_SLOTS: bitmap 4 byte, ô i ứng với byte i/8, bit i%8.
     * 4 byte = 32 bit = 32 ô. Ví dụ ô 0, 1, 10 có dữ liệu:
     *   byte 0 = 0000 0011 = 03 (bit 0, 1) | byte 1 = 0000 0100 = 04 (ô 10 = byte 1, bit 2) -> 03 04 00 00
     * Chỉ đọc cờ, không giải mã gì -> rất nhanh. Ứng dụng dùng nó để biết ô nào cần GET_META.
     */
    private void listSlots(APDU apdu) {
        requirePin();
        byte[] buf = apdu.getBuffer();
        // Util.arrayFillNonAtomic(bArray, bOff, bLen, bValue): ghi giá trị bValue vào bLen byte
        //   bArray[bOff..bOff+bLen). Ở đây: xoá 4 byte đầu của buf về 0 trước khi bật từng bit.
        //   (NonAtomic: không tham gia transaction - như arrayCopyNonAtomic.)
        Util.arrayFillNonAtomic(buf, (short) 0, (short) 4, (byte) 0);
        for (short i = 0; i < SLOTS; i++) {
            if (vault[(short) (i * SLOT_SIZE + O_FLAG)] == 1) {
                setBit(buf, i);
            }
        }
        apdu.setOutgoingAndSend((short) 0, (short) 4);
    }

    /**
     * 0x51 ADD_ENTRY: ghi thông tin vào ô trống đầu tiên, trả về số ô.
     * Ví dụ data: 10 06 "Google" | 12 03 "lan" | 14 01 01  (dịch vụ, tên đăng nhập, nhóm 1)
     * Mật khẩu gửi riêng sau đó bằng SET_PASSWORD với P1 = số ô nhận được.
     * Thẻ kiểm tra TLV trước khi mã hoá -> dữ liệu trong két luôn đúng định dạng (SEARCH dựa vào điều này).
     */
    private void addEntry(APDU apdu) {
        requirePin();
        byte[] buf = apdu.getBuffer();
        short lc = receive(apdu);
        checkMeta(buf, ISO7816.OFFSET_CDATA, lc);

        // Tìm ô trống đầu tiên: bỏ qua các ô có cờ = 1. Hết 32 ô mà không có ô trống -> 6A84.
        short slot = 0;
        while (slot < SLOTS && vault[(short) (slot * SLOT_SIZE + O_FLAG)] == 1) {
            slot++;
        }
        if (slot == SLOTS) {
            ISOException.throwIt(SW_FULL);
        }
        // base = vị trí đầu ô trong mảng vault; các phần trong ô tính bằng base + O_xxx
        short base = (short) (slot * SLOT_SIZE);
        short n = encryptToWork(buf, ISO7816.OFFSET_CDATA, lc);
        // Transaction: ghi blob thông tin, độ dài, đặt "chưa có mật khẩu" (pwLen = 0) và bật cờ
        // "có dữ liệu" - tất cả cùng lúc. Không bao giờ có ô cờ = 1 mà thông tin còn dở dang.

        JCSystem.beginTransaction();
        Util.arrayCopy(work, (short) 0, vault, (short) (base + O_META), n);
        vault[(short) (base + O_META_LEN)] = (byte) n;
        vault[(short) (base + O_PW_LEN)] = 0;
        vault[(short) (base + O_FLAG)] = 1;
        JCSystem.commitTransaction();

        // Trả về 1 byte: số ô vừa ghi (0..31)
        buf[0] = (byte) slot;
        apdu.setOutgoingAndSend((short) 0, (short) 1);
    }

    /**
     * 0x52 UPDATE_META - sửa thông tin của ô P1 (ô phải đang có dữ liệu). Phần mật khẩu giữ nguyên.
     * Gửi lại TOÀN BỘ TLV mới (không sửa từng trường riêng lẻ).
     */
    private void updateMeta(APDU apdu) {
        requirePin();
        byte[] buf = apdu.getBuffer();
        short base = usedSlotBase(buf);
        short lc = receive(apdu);
        checkMeta(buf, ISO7816.OFFSET_CDATA, lc);
        short n = encryptToWork(buf, ISO7816.OFFSET_CDATA, lc);

        JCSystem.beginTransaction();
        Util.arrayCopy(work, (short) 0, vault, (short) (base + O_META), n);
        vault[(short) (base + O_META_LEN)] = (byte) n;
        JCSystem.commitTransaction();
    }

    /**
     * 0x53 SET_PASSWORD - đặt / đổi mật khẩu của ô P1 (1-64 byte).
     * Mật khẩu được mã hoá NGAY TRÊN THẺ bằng MK; máy tính không bao giờ biết MK.
     */
    private void setPassword(APDU apdu) {
        requirePin();
        byte[] buf = apdu.getBuffer();
        short base = usedSlotBase(buf);
        short lc = receive(apdu);
        if (lc == 0 || lc > PW_MAX) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        short n = encryptToWork(buf, ISO7816.OFFSET_CDATA, lc);

        JCSystem.beginTransaction();
        Util.arrayCopy(work, (short) 0, vault, (short) (base + O_PW), n);
        vault[(short) (base + O_PW_LEN)] = (byte) n;
        JCSystem.commitTransaction();
    }

    /**
     * 0x54 GET_META và 0x55 GET_PASSWORD: giải mã một phần của ô rồi gửi ra.
     * Hai lệnh chỉ khác nhau ở phần nào trong ô, nên truyền offset vào làm tham số:
     *   GET_META    : lenOff = O_META_LEN, blobOff = O_META
     *   GET_PASSWORD: lenOff = O_PW_LEN,   blobOff = O_PW
     * (Tách riêng 2 lệnh để ứng dụng có thể hiện danh sách mà không phải giải mã mật khẩu.)
     */
    private void getSlotBlob(APDU apdu, short lenOff, short blobOff) {
        requirePin();
        byte[] buf = apdu.getBuffer();
        short base = usedSlotBase(buf);
        short len = (short) (vault[(short) (base + lenOff)] & 0xFF);
        if (len == 0) {
            ISOException.throwIt(SW_DATA_NOT_FOUND);
        }
        short n = decryptToScratch(vault, (short) (base + blobOff), len);
        sendScratch(apdu, n);
    }

    /**
     * 0x56 DELETE_ENTRY - xoá ô P1.
     * Không cần transaction: chỉ cần ghi được 1 byte cờ = 0 là ô đã bị coi là trống. Phần xoá
     * dữ liệu phía sau chỉ là "dọn dẹp" cho sạch; nếu rút thẻ giữa chừng thì phần còn sót lại
     * vẫn là bản mã (không đọc được) và sẽ bị ghi đè khi ô được dùng lại.
     */
    private void deleteEntry(APDU apdu) {
        requirePin();
        short base = usedSlotBase(apdu.getBuffer());
        // Ghi 1 byte cờ là nguyên tử: sau dòng này ô đã được coi là trống.
        vault[(short) (base + O_FLAG)] = 0;
        // Điền 0 cho 322 byte còn lại của ô (từ base + 1 tới hết ô)
        Util.arrayFillNonAtomic(vault, (short) (base + 1), (short) (SLOT_SIZE - 1), (byte) 0);
    }

    /**
     * 0x57 SEARCH: tìm từ khoá (không phân biệt hoa thường) trong dịch vụ, URL, tên đăng nhập.
     * Chỉ giải mã phần thông tin; phần mật khẩu không bao giờ bị giải mã khi tìm.
     *
     * Vì dữ liệu được mã hoá, máy tính không tự tìm được -> thẻ phải giải mã từng ô để tìm.
     * Ví dụ tìm "goo" trong mọi nhóm: 80 57 00 00 03 67 6F 6F -> bitmap 4 byte các ô khớp
     * (định dạng bitmap giống LIST_SLOTS). Từ khoá rỗng (Lc = 0) = lấy mọi ô của nhóm đó.
     */
    private void search(APDU apdu) {
        requirePin();
        byte[] buf = apdu.getBuffer();
        byte p1 = buf[ISO7816.OFFSET_P1];
        // Đổi P1 thành nhóm cần lọc. Lưu ý p1 là byte có dấu: 0x80 đọc ra là -128, nên phải so
        // riêng với SEARCH_GROUP_OTHER; điều kiện "p1 > 0 && p1 <= 5" tự loại các giá trị âm.
        short group; // -1 = mọi nhóm
        if (p1 == 0) {
            group = -1;
        } else if (p1 == SEARCH_GROUP_OTHER) {
            group = 0;
        } else if (p1 > 0 && p1 <= GROUP_MAX) {
            group = p1;
        } else {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
            return;
        }
        short kwLen = receive(apdu);
        if (kwLen > KEYWORD_MAX) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        short kwOff = ISO7816.OFFSET_CDATA;

        // Bitmap kết quả để tạm trong work[0..3], cuối cùng mới chép sang buf
        // (buf[5..] đang chứa từ khoá, phải dùng suốt vòng lặp).
        Util.arrayFillNonAtomic(work, (short) 0, (short) 4, (byte) 0);
        for (short i = 0; i < SLOTS; i++) {
            short base = (short) (i * SLOT_SIZE);
            if (vault[(short) (base + O_FLAG)] != 1) {
                continue;
            }
            // Giải mã thông tin ô i -> TLV rõ nằm trong scratch[0..n)
            short n = decryptToScratch(vault, (short) (base + O_META), (short) (vault[(short) (base + O_META_LEN)] & 0xFF));
            if (group >= 0) {
                // Lọc theo nhóm: g = vị trí giá trị của tag 0x14; không có tag nhóm -> nhóm 0 ("khác")
                short g = findTag(scratch, (short) 0, n, TAG_GROUP);
                short entryGroup = g < 0 ? 0 : scratch[g];
                if (entryGroup != group) {
                    continue;
                }
            }
            // Khớp nếu không có từ khoá, hoặc từ khoá xuất hiện trong dịch vụ / URL / tên đăng nhập
            // (|| ngắn mạch: tìm thấy ở trường trước thì không tìm tiếp các trường sau)
            if (kwLen == 0
                    || tagContains(n, TAG_SERVICE, buf, kwOff, kwLen)
                    || tagContains(n, TAG_URL, buf, kwOff, kwLen)
                    || tagContains(n, TAG_USERNAME, buf, kwOff, kwLen)) {
                setBit(work, i);
            }
        }
        // Xoá bản rõ của ô cuối cùng vừa giải mã khỏi RAM
        clearScratch();
        Util.arrayCopyNonAtomic(work, (short) 0, buf, (short) 0, (short) 4);
        apdu.setOutgoingAndSend((short) 0, (short) 4);
    }

    /**
     * 0x58 GEN_PASSWORD: sinh mật khẩu ngẫu nhiên trên thẻ.
     * Bỏ các byte r ≥ 256 - (256 mod n) để không bị thiên lệch modulo,
     * và sinh lại nếu thiếu một loại ký tự đã chọn.
     *
     * Ví dụ: 80 58 10 0F 00 -> P1 = 16 ký tự, P2 = 0x0F = đủ cả 4 loại (thường, hoa, số, ký hiệu).
     * Không cần PIN (chỉ cần thẻ Hoạt động) vì sinh số ngẫu nhiên không lộ dữ liệu nào trong két.
     * Ưu điểm: dùng RNG phần cứng của thẻ, tốt hơn RNG của nhiều máy tính / trình duyệt.
     */
    private void genPassword(APDU apdu) {
        if (cardState != STATE_ACTIVE) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        byte[] buf = apdu.getBuffer();
        short len = (short) (buf[ISO7816.OFFSET_P1] & 0xFF);
        byte flags = buf[ISO7816.OFFSET_P2];
        // Độ dài 8..64; phải chọn ít nhất 1 loại; 4 bit cao của P2 phải = 0 (chỉ có 4 loại ký tự)
        if (len < 8 || len > PW_MAX || flags == 0 || (flags & 0xF0) != 0) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }

        // Bảng ký tự được phép, dựng trong work
        // Vd P2 = 0x05 (thường + số): work = "abc...z0123456789", n = 36.
        // Đủ cả 4 loại: n = 26 + 26 + 10 + 24 = 86.
        short n = 0;
        if ((flags & 0x01) != 0) {
            n = appendRange(n, (byte) 'a', (short) 26);
        }
        if ((flags & 0x02) != 0) {
            n = appendRange(n, (byte) 'A', (short) 26);
        }
        if ((flags & 0x04) != 0) {
            n = appendRange(n, (byte) '0', (short) 10);
        }
        if ((flags & 0x08) != 0) {
            n = Util.arrayCopyNonAtomic(SYMBOLS, (short) 0, work, n, (short) SYMBOLS.length);
        }
        // CHỐNG THIÊN LỆCH MODULO: 1 byte ngẫu nhiên r có 256 giá trị, chọn ký tự bằng r % n.
        // Nếu 256 không chia hết cho n thì vài ký tự đầu bảng xuất hiện nhiều hơn.
        // Vd n = 36: 256 = 7 * 36 + 4 -> các ký tự 0..3 có 8 cơ hội, các ký tự khác chỉ 7.
        // Cách sửa: chỉ nhận r < limit = 256 - (256 % n) = 252 (bội số của 36), bỏ r = 252..255 và
        // lấy byte khác -> mọi ký tự có đúng 7 cơ hội như nhau.
        short limit = (short) (256 - (short) (256 % n));

        // "Bể" byte ngẫu nhiên: scratch[0..63]. pos = RND_BATCH nghĩa là bể đang rỗng ->
        // lần đầu vào vòng lặp sẽ nạp đầy ngay. Dùng hết 64 byte thì nạp lô mới.
        short pos = RND_BATCH; // vị trí trong bể byte ngẫu nhiên (scratch)
        // Thử tối đa 100 lần sinh cả mật khẩu (thực tế gần như luôn đạt ngay lần 1-2)
        for (short attempt = 0; attempt < 100; attempt++) {
            for (short i = 0; i < len; i++) {
                short r;
                do {
                    if (pos == RND_BATCH) {
                        rng.nextBytes(scratch, (short) 0, RND_BATCH);
                        pos = 0;
                    }
                    r = (short) (scratch[pos++] & 0xFF);
                } while (r >= limit);   // r rơi vào vùng bị loại -> lấy byte khác
                // Ghi thẳng ký tự thứ i của mật khẩu vào APDU buffer
                buf[i] = work[(short) (r % n)];
            }
            // Mật khẩu phải có MỖI loại đã chọn ít nhất 1 ký tự (vd chọn có số mà không ra số
            // nào thì sinh lại). charClasses trả về mặt nạ các loại thực sự có, so với flags.
            if (charClasses(buf, len) == flags) {
                clearScratch();
                apdu.setOutgoingAndSend((short) 0, len);
                return;
            }
        }
        // 100 lần đều thiếu loại ký tự (gần như không thể xảy ra) -> 6F00
        ISOException.throwIt(ISO7816.SW_UNKNOWN);
    }

    // =====================================================================
    // MỞ RỘNG - Sao lưu và khôi phục
    // =====================================================================

    /**
     * 0x60 BACKUP_BEGIN: bọc MK bằng khoá dẫn xuất từ passphrase.
     * Trả về backupSalt(16) | AES(BK, MK)(16) | AES(MK, BACKUP_CHECK)(16).
     *
     * Ý TƯỞNG SAO LƯU: dữ liệu két đã được mã hoá bằng MK, nên chỉ cần chép NGUYÊN các blob ra
     * ngoài (BACKUP_READ), cộng thêm MK được bọc bằng khoá BK suy ra từ passphrase người dùng tự
     * chọn. File sao lưu vì vậy vô dụng nếu không biết passphrase.
     *
     * Quy trình sao lưu (máy tính làm):
     *   1. VERIFY_PIN
     *   2. BACKUP_BEGIN(passphrase)       -> lưu 48 byte header
     *   3. LIST_SLOTS                     -> biết các ô có dữ liệu
     *   4. Với mỗi ô: BACKUP_READ P2 = 0 (thông tin) và P2 = 1 (mật khẩu) -> lưu các blob
     *
     * Giá trị kiểm tra AES(MK, "VAULTBACKUPCHECK") để lúc khôi phục biết passphrase đúng hay sai:
     * giải mã bằng khoá sai KHÔNG báo lỗi mà chỉ ra 16 byte rác, nên cần một phép thử như vậy.
     *
     * Hạn chế: BK chỉ là 1 lần SHA-256, kẻ có file sao lưu có thể thử passphrase rất nhanh trên máy
     * tính. Thực tế nên dùng hàm dẫn xuất chậm (PBKDF2, Argon2), nhưng thẻ khó chạy những hàm này
     * -> bắt buộc passphrase tối thiểu 8 ký tự, và nên chọn passphrase dài.
     */
    private void backupBegin(APDU apdu) {
        requirePin();
        byte[] buf = apdu.getBuffer();
        short lc = receive(apdu);
        checkPassphrase(lc);
        session[0] &= (byte) ~SES_BACKUP;

        // Dựng 48 byte kết quả trong work:  [0..15] salt | [16..31] MK đã bọc | [32..47] giá trị kiểm tra

        // backupSalt ngẫu nhiên mới cho mỗi lần sao lưu -> work[0..15]
        rng.nextBytes(work, (short) 0, SALT_LEN);
        // BK = SHA256(backupSalt | passphrase)[0..15]
        // (salt = work[0..15]; passphrase = toàn bộ data của APDU: buf[OFFSET_CDATA..+lc))
        hashWithSalt(work, (short) 0, buf, ISO7816.OFFSET_CDATA, lc, scratch, S_TMP);
        // setKey chỉ đọc 16 byte (khoá 128 bit) -> tự lấy 16 byte đầu của hash 32 byte
        kekKey.setKey(scratch, S_TMP);
        // Lấy giá trị MK ra khỏi sessionMk vào scratch[S_MK] để mã hoá nó
        // key.getKey(keyData, kOff): ngược với setKey - chép giá trị khoá ra keyData[kOff..],
        //   trả về số byte (16).
        sessionMk.getKey(scratch, S_MK);
        // work[16..31] = AES(BK, MK). Không truyền IV -> IV = 0; chấp nhận được vì chỉ 1 khối
        // và mỗi lần BK đều khác (do salt mới).
        // aesCbc.init(key, mode): chọn khoá và chiều (MODE_ENCRYPT mã hoá / MODE_DECRYPT giải mã).
        //   Bản có thêm (ivBuf, ivOff, ivLen) để truyền IV - xem encryptToWork.
        // aesCbc.doFinal(inBuff, inOffset, inLength, outBuff, outOffset):
        //   xử lý inBuff[inOffset..inOffset+inLength) và ghi kết quả vào outBuff[outOffset..],
        //   trả về số byte đã ghi. Vì NOPAD nên inLength phải là bội số của 16, không thì
        //   CryptoException. Ở đây: mã hoá 16 byte scratch[S_MK..] -> work[16..31].
        aesCbc.init(kekKey, Cipher.MODE_ENCRYPT);
        aesCbc.doFinal(scratch, S_MK, KEY_LEN, work, SALT_LEN);
        kekKey.clearKey();
        // work[32..47] = AES(MK, "VAULTBACKUPCHECK")
        aesCbc.init(sessionMk, Cipher.MODE_ENCRYPT);
        aesCbc.doFinal(BACKUP_CHECK, (short) 0, KEY_LEN, work, (short) (SALT_LEN + KEY_LEN));
        // Xoá MK rõ và BK khỏi scratch
        clearScratch();

        session[0] |= SES_BACKUP;
        Util.arrayCopyNonAtomic(work, (short) 0, buf, (short) 0, BACKUP_HEADER_LEN);
        apdu.setOutgoingAndSend((short) 0, BACKUP_HEADER_LEN);
    }

    /**
     * 0x61 BACKUP_READ: trả blob đã mã hoá của một ô, giữ nguyên (không giải mã).
     * Chỉ dùng được sau BACKUP_BEGIN trong cùng phiên (cờ SES_BACKUP).
     * P1 = ô, P2 = 0 phần thông tin / 1 phần mật khẩu.
     */
    private void backupRead(APDU apdu) {
        requirePin();
        if ((session[0] & SES_BACKUP) == 0) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        byte[] buf = apdu.getBuffer();
        byte part = buf[ISO7816.OFFSET_P2];
        if (part != 0 && part != 1) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
        short base = usedSlotBase(buf);
        short len = (short) (vault[(short) (base + (part == 0 ? O_META_LEN : O_PW_LEN))] & 0xFF);
        if (len == 0) {
            ISOException.throwIt(SW_DATA_NOT_FOUND);
        }
        Util.arrayCopyNonAtomic(vault, (short) (base + (part == 0 ? O_META : O_PW)), buf, (short) 0, len);
        apdu.setOutgoingAndSend((short) 0, len);
    }

    /**
     * 0x62 RESTORE_BEGIN: lenPass | passphrase | backupSalt(16) | AES(BK, MK cũ)(16) | check(16).
     * Gỡ MK cũ vào restoreMk; nếu AES(MK cũ, BACKUP_CHECK) không khớp thì passphrase sai (6300).
     *
     * Khôi phục thường làm trên một THẺ KHÁC (thẻ mới, đã ISSUE với PIN và MK riêng của nó):
     *   1. VERIFY_PIN (PIN của thẻ mới)
     *   2. RESTORE_BEGIN(passphrase + 48 byte header)  -> thẻ có MK cũ trong restoreMk (RAM)
     *   3. Với mỗi ô trong file: RESTORE_WRITE P2 = 0 rồi P2 = 1
     * Thẻ mới tự giải mã bằng MK cũ và mã hoá lại bằng MK của nó. MK cũ không bao giờ ra khỏi thẻ.
     */
    private void restoreBegin(APDU apdu) {
        requirePin();
        byte[] buf = apdu.getBuffer();
        short lc = receive(apdu);
        session[0] &= (byte) ~SES_RESTORE;
        restoreMk.clearKey();

        short off = ISO7816.OFFSET_CDATA;
        // Tổng độ dài phải đúng = 1 (byte lenPass) + passLen + 48
        short passLen = (short) (buf[off++] & 0xFF);
        if ((short) (1 + passLen + BACKUP_HEADER_LEN) != lc) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        checkPassphrase(passLen);
        short passOff = off;
        short saltOff = (short) (passOff + passLen);
        short wrappedMkOff = (short) (saltOff + SALT_LEN);
        short checkOff = (short) (wrappedMkOff + KEY_LEN);

        // Tính lại BK từ salt trong header + passphrase vừa nhập, rồi giải mã ra "MK cũ"
        // (nếu passphrase sai thì đây chỉ là 16 byte rác - phép thử bên dưới sẽ phát hiện).
        hashWithSalt(buf, saltOff, buf, passOff, passLen, scratch, S_TMP);
        kekKey.setKey(scratch, S_TMP);
        aesCbc.init(kekKey, Cipher.MODE_DECRYPT);
        aesCbc.doFinal(buf, wrappedMkOff, KEY_LEN, scratch, S_MK);
        kekKey.clearKey();
        restoreMk.setKey(scratch, S_MK);

        // Phép thử: tự mã hoá "VAULTBACKUPCHECK" bằng MK vừa gỡ ra, so với giá trị kiểm tra trong
        // header. Khớp -> MK đúng -> passphrase đúng.
        aesCbc.init(restoreMk, Cipher.MODE_ENCRYPT);
        aesCbc.doFinal(BACKUP_CHECK, (short) 0, KEY_LEN, scratch, S_TMP);
        boolean passphraseOk = Util.arrayCompare(scratch, S_TMP, buf, checkOff, KEY_LEN) == 0;
        clearScratch();
        if (!passphraseOk) {
            restoreMk.clearKey();
            ISOException.throwIt(SW_VERIFY_FAILED);
        }
        session[0] |= SES_RESTORE;
    }

    /**
     * 0x63 RESTORE_WRITE: P1 = ô đích, P2 = 0 thông tin / 1 mật khẩu, dữ liệu = blob của thẻ cũ.
     * Giải mã bằng MK cũ, kiểm tra, rồi mã hoá lại bằng MK của thẻ này.
     * Phần thông tin (P2 = 0) tạo lại ô từ đầu, nên phải gửi trước phần mật khẩu.
     */
    private void restoreWrite(APDU apdu) {
        requirePin();
        // key.isInitialized(): true nếu khoá đã được setKey và chưa bị clearKey / xoá do deselect.
        if ((session[0] & SES_RESTORE) == 0 || !restoreMk.isInitialized()) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        byte[] buf = apdu.getBuffer();
        byte part = buf[ISO7816.OFFSET_P2];
        short slot = (short) (buf[ISO7816.OFFSET_P1] & 0xFF);
        if ((part != 0 && part != 1) || slot >= SLOTS) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
        short base = (short) (slot * SLOT_SIZE);
        if (part == 1 && vault[(short) (base + O_FLAG)] != 1) {
            ISOException.throwIt(SW_DATA_NOT_FOUND);
        }
        short lc = receive(apdu);
        short maxBlob = part == 0 ? BLOB_MAX : PW_BLOB_MAX;
        // Blob hợp lệ: ít nhất IV + 1 khối (32 byte), không vượt giới hạn, và là bội số của 16
        // ((lc & 0x0F) != 0 nghĩa là 4 bit thấp khác 0, tức lc không chia hết cho 16)
        if (lc < (short) (IV_LEN + 16) || lc > maxBlob || (lc & 0x0F) != 0) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        // Giải mã bằng MK CŨ (restoreMk) -> bản rõ ở scratch[0..n). Blob hỏng -> unpad ném 6984.
        short n = decryptToScratch(restoreMk, buf, ISO7816.OFFSET_CDATA, lc);
        // Kiểm tra lại nội dung như khi người dùng nhập mới (không tin dữ liệu từ file)
        if (part == 0) {
            checkMeta(scratch, (short) 0, n);
        } else if (n == 0 || n > PW_MAX) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        // Mã hoá lại bằng MK của thẻ NÀY (encryptToWork dùng sessionMk) -> work[0..m)
        short m = encryptToWork(scratch, (short) 0, n);

        JCSystem.beginTransaction();
        if (part == 0) {
            Util.arrayCopy(work, (short) 0, vault, (short) (base + O_META), m);
            vault[(short) (base + O_META_LEN)] = (byte) m;
            vault[(short) (base + O_PW_LEN)] = 0;
            vault[(short) (base + O_FLAG)] = 1;
        } else {
            Util.arrayCopy(work, (short) 0, vault, (short) (base + O_PW), m);
            vault[(short) (base + O_PW_LEN)] = (byte) m;
        }
        JCSystem.commitTransaction();
    }

    // Passphrase 8..64 byte. "static" vì hàm không dùng field nào của đối tượng.
    private static void checkPassphrase(short len) {
        if (len < PASS_MIN || len > PASS_MAX) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
    }

    // =====================================================================
    // GIAI ĐOẠN 4 - Admin
    // =====================================================================

    /**
     * 0x70 ADMIN_CHALLENGE - bước 1 của xác thực admin (challenge-response bằng AES):
     *   1. Thẻ sinh challenge ngẫu nhiên 16 byte, gửi cho máy chủ quản trị.
     *   2. Máy chủ (biết adminKey) tính AES-128(adminKey, challenge), gửi lại bằng ADMIN_AUTH.
     *   3. Thẻ tự tính giá trị đó và so sánh. Khớp -> bên kia biết adminKey -> đúng là admin.
     * adminKey không bao giờ được gửi qua đường truyền; challenge mới mỗi lần nên không phát lại
     * (replay) được câu trả lời cũ.
     */
    private void adminChallenge(APDU apdu) {
        requireIssuedAlive();
        byte[] buf = apdu.getBuffer();
        rng.nextBytes(adminChallenge, (short) 0, ADMIN_CHAL_LEN);
        // Gộp 2 thao tác bit trong 1 dòng: tắt SES_ADMIN (xin challenge mới = huỷ quyền admin cũ)
        // và bật SES_CHAL (đang chờ câu trả lời)
        session[0] = (byte) ((session[0] & ~SES_ADMIN) | SES_CHAL);
        Util.arrayCopyNonAtomic(adminChallenge, (short) 0, buf, (short) 0, ADMIN_CHAL_LEN);
        apdu.setOutgoingAndSend((short) 0, ADMIN_CHAL_LEN);
    }

    /**
     * 0x71 ADMIN_AUTH: dữ liệu = AES-128-CBC(adminKey, IV = 0, challenge). Mỗi challenge chỉ dùng 1 lần.
     * (Bước 2-3 của xác thực admin, xem ADMIN_CHALLENGE.)
     */
    private void adminAuth(APDU apdu) {
        if ((session[0] & SES_CHAL) == 0) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        // Tắt cờ challenge NGAY, trước khi kiểm tra: dù trả lời đúng hay sai, challenge này đã
        // bị dùng -> kẻ gian không được thử nhiều câu trả lời cho cùng 1 challenge.
        session[0] &= (byte) ~SES_CHAL;
        byte[] buf = apdu.getBuffer();
        short lc = receive(apdu);
        if (lc != ADMIN_CHAL_LEN) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        // Thẻ tự tính câu trả lời đúng = AES(adminKey, challenge) vào scratch[0..15], rồi so với dữ liệu gửi lên
        aesCbc.init(adminKey, Cipher.MODE_ENCRYPT);
        aesCbc.doFinal(adminChallenge, (short) 0, ADMIN_CHAL_LEN, scratch, (short) 0);
        boolean ok = Util.arrayCompare(scratch, (short) 0, buf, ISO7816.OFFSET_CDATA, ADMIN_CHAL_LEN) == 0;
        // Xoá challenge và câu trả lời đúng khỏi RAM trước khi báo kết quả
        Util.arrayFillNonAtomic(adminChallenge, (short) 0, ADMIN_CHAL_LEN, (byte) 0);
        Util.arrayFillNonAtomic(scratch, (short) 0, ADMIN_CHAL_LEN, (byte) 0);
        if (!ok) {
            ISOException.throwIt(SW_NOT_AUTH);
        }
        session[0] |= SES_ADMIN;
    }

    /**
     * 0x72 ADMIN_LOCK: P1 = 1 khoá, 0 mở. Gửi lại lệnh cho thẻ đã ở đúng trạng thái thì vẫn trả 9000.
     * (Tính "idempotent": gửi 1 lần hay nhiều lần kết quả như nhau -> máy chủ gửi lại khi mất kết nối
     *  cũng không lỗi.) Khoá tạm thời, khác REVOKE: dữ liệu vẫn còn, mở khoá là dùng tiếp.
     * Ghi 1 byte cardState là nguyên tử nên không cần transaction.
     */
    private void adminLock(APDU apdu) {
        requireAdmin();
        byte p1 = apdu.getBuffer()[ISO7816.OFFSET_P1];
        if (p1 == 1) {
            if (cardState == STATE_ACTIVE) {
                cardState = STATE_ADMIN_LOCKED;
                // Phiên người dùng (nếu có) bị huỷ ngay
                session[0] &= (byte) ~(SES_PIN | SES_SIG);
                sessionMk.clearKey();
            } else if (cardState != STATE_ADMIN_LOCKED) {
                ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
            }
        } else if (p1 == 0) {
            if (cardState == STATE_ADMIN_LOCKED) {
                cardState = STATE_ACTIVE;
            } else if (cardState != STATE_ACTIVE) {
                ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
            }
        } else {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
    }

    /**
     * 0x73 REVOKE: thu hồi vĩnh viễn, xoá MK đã bọc nên dữ liệu không giải mã được nữa.
     * (Crypto-erase: xoá 32 byte mkByPin + mkByPuk là đủ, thay vì xoá hơn 13 KB dữ liệu.)
     * Không có lệnh nào đưa thẻ ra khỏi trạng thái Thu hồi.
     */
    private void revoke() {
        requireAdmin();
        requireIssuedAlive();
        wipeKeysAndSetState(STATE_REVOKED);
    }

    // =====================================================================
    // Hàm hỗ trợ: điều kiện
    // =====================================================================

    /** Lệnh cần PIN: thẻ Hoạt động (6985) và phiên đã xác thực PIN (6982). */
    private void requirePin() {
        if (cardState != STATE_ACTIVE) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        // Kiểm tra 2 lớp: cờ SES_PIN bật VÀ sessionMk thật sự đã có giá trị (isInitialized).
        // Lớp thứ 2 là "phòng hờ": nếu vì lý do nào đó cờ còn mà khoá đã mất thì cũng không chạy tiếp.
        if ((session[0] & SES_PIN) == 0 || !sessionMk.isInitialized()) {
            ISOException.throwIt(SW_NOT_AUTH);
        }
    }

    /** Lệnh cần quyền admin: phiên đã qua ADMIN_CHALLENGE + ADMIN_AUTH (6982). Độc lập với PIN. */
    private void requireAdmin() {
        if ((session[0] & SES_ADMIN) == 0) {
            ISOException.throwIt(SW_NOT_AUTH);
        }
    }

    /** Đã phát hành, chưa thu hồi và chưa vô hiệu. */
    private void requireIssuedAlive() {
        if (cardState != STATE_ACTIVE && cardState != STATE_PIN_BLOCKED && cardState != STATE_ADMIN_LOCKED) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
    }

    /** VERIFY_PIN và CHANGE_PIN chỉ chạy ở trạng thái Hoạt động. */
    private void requirePinUsable() {
        if (cardState == STATE_PIN_BLOCKED) {
            ISOException.throwIt(SW_BLOCKED);
        }
        if (cardState != STATE_ACTIVE) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
    }

    /**
     * Kiểm tra P1 là một ô đang có dữ liệu, trả về vị trí đầu ô trong mảng vault.
     * Gom vào 1 hàm vì có tới 6 lệnh cần (UPDATE_META, SET_PASSWORD, GET_META, GET_PASSWORD,
     * DELETE_ENTRY, BACKUP_READ). P1 >= 32 -> 6A86; ô trống -> 6A88.
     */
    private short usedSlotBase(byte[] buf) {
        short slot = (short) (buf[ISO7816.OFFSET_P1] & 0xFF);
        if (slot >= SLOTS) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
        short base = (short) (slot * SLOT_SIZE);
        if (vault[(short) (base + O_FLAG)] != 1) {
            ISOException.throwIt(SW_DATA_NOT_FOUND);
        }
        return base;
    }

    // =====================================================================
    // Hàm hỗ trợ: PIN / PUK
    // =====================================================================

    /**
     * Kiểm tra PIN. Sai thì ném 63Cx (còn x lần) hoặc 6983 (vừa bị khoá).
     * Bộ đếm được giảm TRƯỚC khi so sánh: nếu kẻ tấn công rút thẻ ngay sau khi
     * so sánh để không bị trừ lượt, thì lượt đó đã bị trừ rồi.
     */
    private void checkPinOrThrow(byte[] pinBuf, short pinOff, short pinLen) {
        // Hết lượt từ trước (bình thường không tới được đây vì thẻ đã ở Khoá PIN - phòng hờ)
        if (pinTriesLeft == 0) {
            blockPin();
        }
        // Trừ lượt TRƯỚC (ghi 1 byte EEPROM, nguyên tử)
        pinTriesLeft--;
        // Băm PIN nhập vào với salt đã lưu, so với hash đã lưu
        hashWithSalt(pinSalt, pinBuf, pinOff, pinLen, scratch, S_TMP);
        boolean pinMatches = Util.arrayCompare(scratch, S_TMP, pinHash, (short) 0, HASH_LEN) == 0;
        // Lưu kết quả vào biến pinMatches rồi xoá hash tạm ngay, để dù đúng hay sai nó cũng không nằm lại RAM
        Util.arrayFillNonAtomic(scratch, S_TMP, HASH_LEN, (byte) 0);
        if (pinMatches) {
            // Đúng -> trả lại đủ 3 lượt
            pinTriesLeft = PIN_TRIES_MAX;
            return;
        }
        if (pinTriesLeft == 0) {
            blockPin();
        }
        ISOException.throwIt((short) (SW_WRONG_CODE_BASE | pinTriesLeft));
    }

    /**
     * Khoá PIN: đóng phiên, chuyển sang Khoá PIN, ném 6983. Hàm luôn kết thúc bằng exception,
     * nên ở chỗ gọi, code phía sau "blockPin();" sẽ không chạy.
     * Dữ liệu và MK đã bọc vẫn còn -> mở lại được bằng UNBLOCK_PUK.
     */
    private void blockPin() {
        clearSession();
        cardState = STATE_PIN_BLOCKED;
        ISOException.throwIt(SW_BLOCKED);
    }

    /** Xoá MK đã bọc và chuyển sang trạng thái cuối (Thu hồi / Vô hiệu). */
    private void wipeKeysAndSetState(byte state) {
        clearSession();
        // Lưu ý: các hàm *NonAtomic KHÔNG tham gia transaction, nên ở đây ghi từng byte.
        // (Util không có hàm "arrayFill" atomic. Gán từng phần tử thì có tham gia transaction.)
        // Xoá MK đã bọc và đổi trạng thái cùng lúc: không bao giờ có thẻ "Thu hồi" mà MK vẫn còn.
        JCSystem.beginTransaction();
        for (short i = 0; i < KEY_LEN; i++) {
            mkByPin[i] = 0;
            mkByPuk[i] = 0;
        }
        cardState = state;
        JCSystem.commitTransaction();
    }

    /**
     * Từ mã (PIN hoặc PUK) và MK trong scratch[S_MK], sinh salt mới rồi tính:
     *   hash      = SHA256(salt | code)
     *   KEK       = SHA256(kekSalt | code)[0..15]
     *   wrappedMk = AES-CBC(KEK, IV = 0, MK)
     * Mã nằm ở codeBuf[codeOff..codeOff+codeLen) (thường là bộ đệm APDU).
     * Bốn kết quả (salt, kekSalt, hash, wrappedMk) ghi vào scratch tại 4 vị trí truyền vào.
     *
     * Vì sao cần 2 salt khác nhau (salt cho hash, kekSalt cho KEK)?
     *   Nếu dùng chung 1 salt thì KEK = 16 byte đầu của hash đã lưu trong EEPROM. Ai đọc được
     *   pinHash là có luôn KEK -> gỡ được MK mà không cần biết PIN. Hai salt khác nhau làm hai
     *   giá trị độc lập: biết hash cũng không suy ra được KEK.
     *
     * Các tham số outXxxOff là VỊ TRÍ trong scratch để ghi kết quả (truyền S_PIN_xxx hoặc
     * S_PUK_xxx), nhờ đó cùng 1 hàm dùng được cho cả PIN lẫn PUK.
     */
    private void deriveCredential(byte[] codeBuf, short codeOff, short codeLen,
            short outSaltOff, short outKekSaltOff, short outHashOff, short outWrappedMkOff) {
        // 2 salt mới ngẫu nhiên (mỗi lần đổi PIN là salt mới)
        rng.nextBytes(scratch, outSaltOff, SALT_LEN);
        rng.nextBytes(scratch, outKekSaltOff, SALT_LEN);
        // hash = SHA256(salt | code) -> scratch[outHashOff]
        hashWithSalt(scratch, outSaltOff, codeBuf, codeOff, codeLen, scratch, outHashOff);
        // KEK = SHA256(kekSalt | code) -> tạm ở scratch[S_TMP], nạp 16 byte đầu vào kekKey
        hashWithSalt(scratch, outKekSaltOff, codeBuf, codeOff, codeLen, scratch, S_TMP);
        kekKey.setKey(scratch, S_TMP);
        // wrappedMk = AES(KEK, MK) -> scratch[outWrappedMkOff]. MK đúng 16 byte = 1 khối nên không cần padding.
        aesCbc.init(kekKey, Cipher.MODE_ENCRYPT);
        aesCbc.doFinal(scratch, S_MK, KEY_LEN, scratch, outWrappedMkOff);
        // Xoá KEK ngay sau khi dùng (cả trong khoá lẫn bản trong scratch)
        kekKey.clearKey();
        Util.arrayFillNonAtomic(scratch, S_TMP, HASH_LEN, (byte) 0);
    }

    /**
     * Gỡ bọc MK: scratch[S_MK] = AES-CBC-decrypt(KEK, wrappedMk), với
     *   KEK = SHA256(kekSalt | code)[0..15]
     *   code      : PIN hoặc PUK người dùng nhập, nằm ở codeBuf[codeOff..codeOff+codeLen)
     *   kekSalt   : pinKekSalt hoặc pukKekSalt (đi cùng loại mã)
     *   wrappedMk : mkByPin hoặc mkByPuk - bản MK đã bọc lưu trong EEPROM
     * Chỉ gọi SAU KHI đã kiểm tra PIN/PUK đúng: với mã sai, hàm vẫn chạy nhưng ra MK rác.
     */
    private void unwrapMk(byte[] codeBuf, short codeOff, short codeLen, byte[] kekSalt, byte[] wrappedMk) {
        // KEK -> tạm ở scratch[S_TMP], nạp 16 byte đầu vào kekKey
        hashWithSalt(kekSalt, codeBuf, codeOff, codeLen, scratch, S_TMP);
        kekKey.setKey(scratch, S_TMP);
        aesCbc.init(kekKey, Cipher.MODE_DECRYPT);
        aesCbc.doFinal(wrappedMk, (short) 0, KEY_LEN, scratch, S_MK);
        kekKey.clearKey();
        Util.arrayFillNonAtomic(scratch, S_TMP, HASH_LEN, (byte) 0);
    }

    /** Chép thông tin PIN mới từ scratch sang EEPROM. Gọi bên trong transaction. */
    private void storePinCredential() {
        Util.arrayCopy(scratch, S_PIN_SALT, pinSalt, (short) 0, SALT_LEN);
        Util.arrayCopy(scratch, S_PIN_KEKSALT, pinKekSalt, (short) 0, SALT_LEN);
        Util.arrayCopy(scratch, S_PIN_HASH, pinHash, (short) 0, HASH_LEN);
        Util.arrayCopy(scratch, S_MK_BY_PIN, mkByPin, (short) 0, KEY_LEN);
    }

    /**
     * Tính SHA256(salt | data) và ghi 32 byte kết quả ra outBuf[outOff..outOff+32).
     *   salt : 16 byte (SALT_LEN) trong saltBuf, bắt đầu tại saltOff
     *   data : dataLen byte trong dataBuf, bắt đầu tại dataOff (PIN, PUK hoặc passphrase)
     * Quy ước đặt tên: xxxBuf là mảng chứa dữ liệu, xxxOff là vị trí bắt đầu trong mảng đó,
     * xxxLen là số byte - vì Java Card không có kiểu "mảng con", nên mỗi đoạn dữ liệu phải truyền
     * đủ bộ 3 (mảng, vị trí, độ dài).
     *
     * Có 2 phiên bản cùng tên (overloading, giống Java thường): bản ngắn dưới đây dùng khi salt
     * nằm ở đầu một mảng riêng (pinSalt, pukSalt...), nó chỉ gọi bản đầy đủ với saltOff = 0.
     */
    private void hashWithSalt(byte[] saltBuf, byte[] dataBuf, short dataOff, short dataLen,
            byte[] outBuf, short outOff) {
        hashWithSalt(saltBuf, (short) 0, dataBuf, dataOff, dataLen, outBuf, outOff);
    }

    private void hashWithSalt(byte[] saltBuf, short saltOff, byte[] dataBuf, short dataOff, short dataLen,
            byte[] outBuf, short outOff) {
        // Băm 2 đoạn dữ liệu nằm ở 2 mảng khác nhau mà không cần ghép chúng lại trước:
        //   reset()  : xoá trạng thái cũ (phòng lần trước bị dở dang do exception)
        //   update() : đưa phần đầu (salt) vào, chưa ra kết quả
        //   doFinal(): đưa phần cuối (data) vào và ghi hash 32 byte ra outBuf
        sha256.reset();
        sha256.update(saltBuf, saltOff, SALT_LEN);
        sha256.doFinal(dataBuf, dataOff, dataLen, outBuf, outOff);
    }

    // =====================================================================
    // Hàm hỗ trợ: mã hoá dữ liệu bằng Master Key
    // =====================================================================

    /**
     * blob = IV | AES-128-CBC(MK, IV, pad(plaintext)), IV ngẫu nhiên mới mỗi lần ghi.
     * Kết quả nằm trong work[0..], trả về độ dài blob.
     */
    private short encryptToWork(byte[] src, short off, short len) {
        // Chép bản rõ sang scratch vì cần chỗ trống phía sau để thêm padding
        // (khi src chính là scratch và off = 0, như ở restoreWrite, lệnh chép này không đổi gì)
        Util.arrayCopyNonAtomic(src, off, scratch, (short) 0, len);
        // Thêm padding cho đủ bội số của 16 (vì aesCbc là NOPAD)
        short padded = pad(scratch, len);
        // IV ngẫu nhiên MỚI cho mỗi lần ghi, đặt luôn ở đầu blob work[0..15].
        // Nhờ vậy cùng một mật khẩu ghi 2 lần vẫn ra 2 bản mã khác nhau -> nhìn bản mã không đoán
        // được hai ô có cùng mật khẩu hay không.
        rng.nextBytes(work, (short) 0, IV_LEN);
        // aesCbc.init(key, mode, ivBuf, ivOff, ivLen): như init 2 tham số, thêm IV lấy từ
        //   ivBuf[ivOff..ivOff+ivLen) (ở đây là work[0..15] vừa sinh ngẫu nhiên). ivLen phải = 16.
        aesCbc.init(sessionMk, Cipher.MODE_ENCRYPT, work, (short) 0, IV_LEN);
        // Bản mã ghi ngay sau IV: work[16..16+n). doFinal trả về n = số byte bản mã (= padded).
        short n = aesCbc.doFinal(scratch, (short) 0, padded, work, IV_LEN);
        // Xoá bản rõ khỏi scratch
        Util.arrayFillNonAtomic(scratch, (short) 0, padded, (byte) 0);
        return (short) (IV_LEN + n);
    }

    /** Giải mã blob (IV | ciphertext) bằng MK của phiên vào scratch[0..], bỏ padding, trả về độ dài bản rõ. */
    private short decryptToScratch(byte[] blob, short off, short blobLen) {
        return decryptToScratch(sessionMk, blob, off, blobLen);
    }

    // Bản đầy đủ: chọn được khoá (sessionMk bình thường, restoreMk khi khôi phục)
    private short decryptToScratch(AESKey key, byte[] blob, short off, short blobLen) {
        // IV lấy từ 16 byte đầu blob; phần còn lại (blobLen - 16) là bản mã
        aesCbc.init(key, Cipher.MODE_DECRYPT, blob, off, IV_LEN);
        short n = aesCbc.doFinal(blob, (short) (off + IV_LEN), (short) (blobLen - IV_LEN), scratch, (short) 0);
        return unpad(scratch, n);
    }

    /**
     * ISO/IEC 9797-1 phương pháp 2: thêm 0x80 rồi 0x00 cho đủ bội số của 16.
     * Vd "abc" (3 byte) -> 61 62 63 80 00 00 00 00 00 00 00 00 00 00 00 00 (16 byte).
     * Luôn thêm ít nhất 1 byte 0x80: dữ liệu đúng 16 byte sẽ thành 32 byte. Nhờ có 0x80 làm
     * "mốc" nên khi bỏ padding luôn biết chính xác dữ liệu thật kết thúc ở đâu.
     * (len & 0x0F) != 0 nghĩa là len chưa chia hết cho 16.
     */
    private static short pad(byte[] b, short len) {
        b[len++] = (byte) 0x80;
        while ((len & 0x0F) != 0) {
            b[len++] = 0;
        }
        return len;
    }

    /**
     * Bỏ padding: đi lùi từ cuối, bỏ qua các byte 0x00, byte gặp đầu tiên phải là 0x80.
     * Vị trí của 0x80 chính là độ dài dữ liệu thật. Không tìm thấy 0x80 -> dữ liệu hỏng
     * hoặc giải mã sai khoá -> 6984.
     */
    private static short unpad(byte[] b, short len) {
        short i = (short) (len - 1);
        while (i >= 0 && b[i] == 0) {
            i--;
        }
        if (i < 0 || b[i] != (byte) 0x80) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        return i;
    }

    /** Gửi n byte bản rõ trong scratch ra ngoài, xoá scratch TRƯỚC khi gửi. */
    private void sendScratch(APDU apdu, short n) {
        byte[] buf = apdu.getBuffer();
        Util.arrayCopyNonAtomic(scratch, (short) 0, buf, (short) 0, n);
        clearScratch();
        apdu.setOutgoingAndSend((short) 0, n);
    }

    // =====================================================================
    // Hàm hỗ trợ: TLV, tìm kiếm, sinh mật khẩu
    // =====================================================================

    /**
     * Kiểm tra chuỗi TLV: tag nằm trong [firstTag, firstTag + số trường), không lặp,
     * độ dài nằm trong [min, max] của trường đó. Trả về mặt nạ bit các tag đã gặp.
     *
     * Ví dụ duyệt "10 06 Google 12 03 lan" (firstTag = 0x10):
     *   off = 0 : tag 10 -> idx 0, l = 6, kiểm tra 1 <= 6 <= 32, nhảy off = 0 + 2 + 6 = 8, seen = 0b001
     *   off = 8 : tag 12 -> idx 2, l = 3, kiểm tra 1 <= 3 <= 48, nhảy off = 8 + 2 + 3 = 13 = end, seen = 0b101
     * Mọi lỗi (thiếu byte, tag lạ, tag lặp, độ dài sai, vượt ra ngoài) đều báo 6A80.
     */
    private static short checkTlv(byte[] buf, short off, short len, byte firstTag, byte[] minLen, byte[] maxLen) {
        short end = (short) (off + len);
        short seen = 0;
        while (off < end) {
            if ((short) (off + 2) > end) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            }
            // idx = số thứ tự của tag (dùng tra bảng min/max); l = độ dài phần giá trị
            short idx = (short) (buf[off] - firstTag);
            short l = (short) (buf[(short) (off + 1)] & 0xFF);
            if (idx < 0 || idx >= (short) maxLen.length) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            }
            // Mỗi tag ứng với 1 bit trong seen; bit đã bật nghĩa là tag này xuất hiện lần 2 -> lỗi
            short bit = (short) (1 << idx);
            if ((seen & bit) != 0 || l < minLen[idx] || l > maxLen[idx]) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            }
            off = (short) (off + 2 + l);
            if (off > end) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            }
            seen |= bit;
        }
        return seen;
    }

    /** TLV thông tin bản ghi: bắt buộc có tên dịch vụ, nhóm phải là 0-5. */
    private static void checkMeta(byte[] buf, short off, short len) {
        short seen = checkTlv(buf, off, len, TAG_SERVICE, META_MIN, META_MAX);
        // Bit 0 = tag 0x10 (dịch vụ) - trường bắt buộc
        if ((seen & 0x01) == 0) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        short g = findTag(buf, off, len, TAG_GROUP);
        if (g >= 0 && (buf[g] < 0 || buf[g] > GROUP_MAX)) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
    }

    /**
     * Tìm tag trong TLV đã kiểm tra, trả về vị trí giá trị (độ dài ở byte ngay trước), hoặc -1.
     * Không kiểm tra lỗi gì vì chỉ dùng cho TLV đã qua checkTlv (dữ liệu chắc chắn đúng định dạng).
     */
    private static short findTag(byte[] buf, short off, short len, byte tag) {
        short end = (short) (off + len);
        while ((short) (off + 2) <= end) {
            if (buf[off] == tag) {
                return (short) (off + 2);
            }
            off = (short) (off + 2 + (buf[(short) (off + 1)] & 0xFF));
        }
        return -1;
    }

    /** Trường tag trong bản thông tin đã giải mã (scratch) có chứa từ khoá không. */
    private boolean tagContains(short metaLen, byte tag, byte[] kw, short kwOff, short kwLen) {
        short v = findTag(scratch, (short) 0, metaLen, tag);
        if (v < 0) {
            return false;
        }
        short vLen = (short) (scratch[(short) (v - 1)] & 0xFF);
        // Tìm chuỗi con kiểu "thô" (giống String.contains nhưng không phân biệt hoa thường):
        // thử đặt từ khoá ở mọi vị trí i, so từng ký tự j; so khớp hết kwLen ký tự -> tìm thấy.
        for (short i = 0; (short) (i + kwLen) <= vLen; i++) {
            short j = 0;
            while (j < kwLen && lower(scratch[(short) (v + i + j)]) == lower(kw[(short) (kwOff + j)])) {
                j++;
            }
            if (j == kwLen) {
                return true;
            }
        }
        return false;
    }

    // Đổi chữ hoa A-Z thành chữ thường: trong ASCII, chữ thường = chữ hoa + 32 ('A' = 65, 'a' = 97)
    private static byte lower(byte c) {
        return (c >= 'A' && c <= 'Z') ? (byte) (c + 32) : c;
    }

    // Bật bit thứ i của bitmap: byte i >> 3 (= i / 8), bit i & 7 (= i % 8).
    // Dịch bit và AND nhanh hơn chia / chia lấy dư trên vi xử lý yếu của thẻ.
    private static void setBit(byte[] bitmap, short i) {
        bitmap[(short) (i >> 3)] |= (byte) (1 << (i & 7));
    }

    // Thêm count ký tự liên tiếp bắt đầu từ first vào work[n...], vd ('a', 26) -> "a..z". Trả về n mới.
    private short appendRange(short n, byte first, short count) {
        for (short i = 0; i < count; i++) {
            work[n++] = (byte) (first + i);
        }
        return n;
    }

    /** Mặt nạ các loại ký tự có trong mật khẩu: bit0 thường, bit1 hoa, bit2 số, bit3 ký hiệu. */
    private static byte charClasses(byte[] b, short len) {
        byte m = 0;
        for (short i = 0; i < len; i++) {
            byte c = b[i];
            if (c >= 'a' && c <= 'z') {
                m |= 0x01;
            } else if (c >= 'A' && c <= 'Z') {
                m |= 0x02;
            } else if (c >= '0' && c <= '9') {
                m |= 0x04;
            } else {
                m |= 0x08;
            }
        }
        return m;
    }

    // =====================================================================
    // Hàm hỗ trợ: kiểm tra định dạng
    // =====================================================================

    /** PIN: 6-12 ký tự ASCII in được (0x20..0x7E). */
    private static void checkPinFormat(byte[] buf, short off, short len) {
        if (len < PIN_MIN || len > PIN_MAX) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        for (short i = 0; i < len; i++) {
            byte c = buf[(short) (off + i)];
            if (c < 0x20 || c > 0x7E) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            }
        }
    }

    /** PUK: đúng 8 chữ số. */
    private static void checkPukFormat(byte[] buf, short off, short len) {
        if (len != PUK_LEN) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        for (short i = 0; i < len; i++) {
            byte c = buf[(short) (off + i)];
            if (c < '0' || c > '9') {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            }
        }
    }

    /** cardId: 8 ký tự ASCII chữ hoa hoặc số, ví dụ SC000001. */
    private static void checkCardId(byte[] buf, short off) {
        for (short i = 0; i < CARD_ID_LEN; i++) {
            byte c = buf[(short) (off + i)];
            if (!((c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z'))) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            }
        }
    }

    // =====================================================================
    // Hàm hỗ trợ: chung
    // =====================================================================

    /**
     * Nhận toàn bộ dữ liệu của lệnh, trả về Lc. Dữ liệu ≤ 255 byte nên một lần là đủ.
     * setIncomingAndReceive() trả về số byte nhận được ở LẦN ĐẦU; getIncomingLength() trả về Lc
     * (tổng số byte lệnh khai báo). Nếu dữ liệu dài hơn buffer, phải gọi thêm receiveBytes() để
     * nhận tiếp. Applet này không cần nên chỉ kiểm tra: chưa nhận đủ thì báo lỗi 6700.
     */
    private static short receive(APDU apdu) {
        short read = apdu.setIncomingAndReceive();
        short lc = apdu.getIncomingLength();
        if (read != lc) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        return lc;
    }

    /** Đóng phiên: tắt mọi cờ (PIN, admin, chữ ký...) và xoá MK + MK khôi phục khỏi RAM. Dùng cho LOGOUT. */
    private void clearSession() {
        session[0] = 0;
        sessionMk.clearKey();
        restoreMk.clearKey();
    }

    /** Xoá toàn bộ 256 byte scratch - gọi sau mỗi thao tác có dữ liệu nhạy cảm (MK, bản rõ, hash). */
    private void clearScratch() {
        Util.arrayFillNonAtomic(scratch, (short) 0, BUF_LEN, (byte) 0);
    }
}
