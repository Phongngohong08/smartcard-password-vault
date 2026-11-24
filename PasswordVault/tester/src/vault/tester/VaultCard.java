package vault.tester;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;

/**
 * Gom các lệnh APDU của VaultApplet thành hàm Java.
 *
 * Không phụ thuộc javax.smartcardio: chỉ cần một Transport gửi/nhận byte[],
 * nên có thể dùng lại trên Android (IsoDep.transceive) sau này.
 */
public class VaultCard {

    /** Gửi một APDU dạng byte và nhận phản hồi (dữ liệu | SW1 SW2). */
    public interface Transport {
        byte[] transmit(byte[] command) throws Exception;
    }

    /** Phản hồi APDU: dữ liệu + SW. */
    public record Resp(byte[] data, int sw) {
        public boolean ok() {
            return sw == 0x9000;
        }

        @Override
        public String toString() {
            return String.format("SW=%04X data=%s", sw, Hex.of(data));
        }
    }

    /** Kết quả GET_STATUS. */
    public record Status(int state, String cardId, int pinTriesLeft, int pukTriesLeft) {}

    public static final byte[] AID = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x00, 0x01 };
    public static final byte[] AUTH_PREFIX = "VAULTAUTH".getBytes(StandardCharsets.US_ASCII);

    public static final int CLA = 0x80;
    public static final int INS_GET_VERSION = 0x01;
    public static final int INS_ISSUE = 0x10;
    public static final int INS_GET_STATUS = 0x11;
    public static final int INS_GET_PUBKEY = 0x12;
    public static final int INS_VERIFY_PIN = 0x20;
    public static final int INS_CHANGE_PIN = 0x21;
    public static final int INS_UNBLOCK_PUK = 0x22;
    public static final int INS_LOGOUT = 0x23;
    public static final int INS_INTERNAL_AUTH = 0x30;
    public static final int INS_GET_SIGNATURE = 0x31;

    public static final int STATE_UNISSUED = 0x00;
    public static final int STATE_ACTIVE = 0x01;
    public static final int STATE_PIN_BLOCKED = 0x02;
    public static final int STATE_ADMIN_LOCKED = 0x03;
    public static final int STATE_REVOKED = 0x04;
    public static final int STATE_DISABLED = 0x05;

    private final Transport transport;

    public VaultCard(Transport transport) {
        this.transport = transport;
    }

    // ------------------------------------------------------------------ APDU thô

    public Resp send(int cla, int ins, int p1, int p2, byte[] data, boolean expectData) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(cla);
        out.write(ins);
        out.write(p1);
        out.write(p2);
        if (data != null && data.length > 0) {
            if (data.length > 255) {
                throw new IllegalArgumentException("Dữ liệu > 255 byte");
            }
            out.write(data.length);
            out.write(data);
        }
        if (expectData) {
            out.write(0x00); // Le = 256
        }
        byte[] r = transport.transmit(out.toByteArray());
        int n = r.length - 2;
        byte[] body = new byte[n];
        System.arraycopy(r, 0, body, 0, n);
        int sw = ((r[n] & 0xFF) << 8) | (r[n + 1] & 0xFF);
        return new Resp(body, sw);
    }

    public Resp send(int ins, int p1, int p2, byte[] data, boolean expectData) throws Exception {
        return send(CLA, ins, p1, p2, data, expectData);
    }

    // ------------------------------------------------------------------ Lệnh

    public Resp select() throws Exception {
        return send(0x00, 0xA4, 0x04, 0x00, AID, false);
    }

    public Resp getVersion() throws Exception {
        return send(INS_GET_VERSION, 0, 0, null, true);
    }

    public Resp issue(String cardId, String pin, String puk, byte[] adminKey) throws Exception {
        return send(INS_ISSUE, 0, 0, issueData(cardId, pin, puk, adminKey), false);
    }

    public static byte[] issueData(String cardId, String pin, String puk, byte[] adminKey) {
        ByteArrayOutputStream d = new ByteArrayOutputStream();
        d.writeBytes(ascii(cardId));
        d.writeBytes(lv(pin));
        d.writeBytes(lv(puk));
        d.writeBytes(adminKey);
        return d.toByteArray();
    }

    public Resp getStatusRaw() throws Exception {
        return send(INS_GET_STATUS, 0, 0, null, true);
    }

    public Status getStatus() throws Exception {
        Resp r = require(getStatusRaw());
        byte[] d = r.data();
        return new Status(d[0] & 0xFF, new String(d, 1, 8, StandardCharsets.US_ASCII).replace('\0', ' ').trim(),
                d[9], d[10]);
    }

    public Resp getPubKeyPart(int p1) throws Exception {
        return send(INS_GET_PUBKEY, p1, 0, null, true);
    }

    /** Đọc khoá công khai RSA bằng 3 lệnh GET_PUBKEY (P1 = 0, 1, 2). */
    public RSAPublicKey getPublicKey() throws Exception {
        byte[] m0 = require(getPubKeyPart(0)).data();
        byte[] m1 = require(getPubKeyPart(1)).data();
        byte[] e = require(getPubKeyPart(2)).data();
        byte[] mod = new byte[m0.length + m1.length];
        System.arraycopy(m0, 0, mod, 0, m0.length);
        System.arraycopy(m1, 0, mod, m0.length, m1.length);
        RSAPublicKeySpec spec = new RSAPublicKeySpec(new BigInteger(1, mod), new BigInteger(1, e));
        return (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(spec);
    }

    public Resp verifyPin(String pin) throws Exception {
        return send(INS_VERIFY_PIN, 0, 0, ascii(pin), false);
    }

    public Resp changePin(String oldPin, String newPin) throws Exception {
        return send(INS_CHANGE_PIN, 0, 0, concat(lv(oldPin), lv(newPin)), false);
    }

    public Resp unblockPuk(String puk, String newPin) throws Exception {
        return send(INS_UNBLOCK_PUK, 0, 0, concat(lv(puk), lv(newPin)), false);
    }

    public Resp logout() throws Exception {
        return send(INS_LOGOUT, 0, 0, null, false);
    }

    public Resp internalAuth(byte[] challenge) throws Exception {
        return send(INS_INTERNAL_AUTH, 0, 0, challenge, false);
    }

    public Resp getSignaturePart(int p1) throws Exception {
        return send(INS_GET_SIGNATURE, p1, 0, null, true);
    }

    /** INTERNAL_AUTH rồi đọc chữ ký 256 byte bằng 2 lệnh GET_SIGNATURE. */
    public byte[] authenticate(byte[] challenge) throws Exception {
        require(internalAuth(challenge));
        return concat(require(getSignaturePart(0)).data(), require(getSignaturePart(1)).data());
    }

    /** Thông điệp mà thẻ ký: "VAULTAUTH" | cardId | challenge. Phần mềm dựng lại để kiểm tra. */
    public static byte[] authMessage(String cardId, byte[] challenge) {
        return concat(concat(AUTH_PREFIX, ascii(cardId)), challenge);
    }

    // ------------------------------------------------------------------ Giai đoạn 2: hồ sơ, ảnh

    public static final int INS_SET_PROFILE = 0x40;
    public static final int INS_GET_PROFILE = 0x41;
    public static final int INS_SET_AVATAR = 0x42;
    public static final int INS_GET_AVATAR = 0x43;
    public static final int AVATAR_CHUNK = 192;

    public Resp setProfile(byte[] tlv) throws Exception {
        return send(INS_SET_PROFILE, 0, 0, tlv, false);
    }

    public Resp getProfile() throws Exception {
        return send(INS_GET_PROFILE, 0, 0, null, true);
    }

    public Resp setAvatarChunk(int index, int total, byte[] data) throws Exception {
        return send(INS_SET_AVATAR, index, total, data, false);
    }

    public Resp getAvatarChunk(int index) throws Exception {
        return send(INS_GET_AVATAR, index, 0, null, true);
    }

    /** Ghi ảnh: chia thành các khối 192 byte, ghi lần lượt từ khối 0. */
    public void writeAvatar(byte[] image) throws Exception {
        int total = (image.length + AVATAR_CHUNK - 1) / AVATAR_CHUNK;
        for (int i = 0; i < total; i++) {
            int from = i * AVATAR_CHUNK;
            byte[] part = java.util.Arrays.copyOfRange(image, from, Math.min(image.length, from + AVATAR_CHUNK));
            require(setAvatarChunk(i, total, part));
        }
    }

    /** Đọc ảnh: hỏi số khối (P1 = 0xFF) rồi đọc từng khối. Trả về mảng rỗng nếu chưa có ảnh. */
    public byte[] readAvatar() throws Exception {
        int total = require(getAvatarChunk(0xFF)).data()[0] & 0xFF;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (int i = 0; i < total; i++) {
            out.writeBytes(require(getAvatarChunk(i)).data());
        }
        return out.toByteArray();
    }

    // ------------------------------------------------------------------ Giai đoạn 3: két mật khẩu

    public static final int INS_LIST_SLOTS = 0x50;
    public static final int INS_ADD_ENTRY = 0x51;
    public static final int INS_UPDATE_META = 0x52;
    public static final int INS_SET_PASSWORD = 0x53;
    public static final int INS_GET_META = 0x54;
    public static final int INS_GET_PASSWORD = 0x55;
    public static final int INS_DELETE_ENTRY = 0x56;
    public static final int INS_SEARCH = 0x57;
    public static final int INS_GEN_PASSWORD = 0x58;

    public static final int TAG_SERVICE = 0x10, TAG_URL = 0x11, TAG_USERNAME = 0x12, TAG_NOTE = 0x13, TAG_GROUP = 0x14;
    public static final int GROUP_OTHER = 0, GROUP_EMAIL = 1, GROUP_SOCIAL = 2, GROUP_BANK = 3, GROUP_WORK = 4,
            GROUP_SHOPPING = 5;
    /** P1 của SEARCH để lọc nhóm "khác" (mã 0), vì P1 = 0 nghĩa là mọi nhóm. */
    public static final int SEARCH_GROUP_OTHER = 0x80;

    public static final int GEN_LOWER = 0x01, GEN_UPPER = 0x02, GEN_DIGIT = 0x04, GEN_SYMBOL = 0x08;

    public Resp listSlots() throws Exception {
        return send(INS_LIST_SLOTS, 0, 0, null, true);
    }

    public Resp addEntry(byte[] metaTlv) throws Exception {
        return send(INS_ADD_ENTRY, 0, 0, metaTlv, true);
    }

    public Resp updateMeta(int slot, byte[] metaTlv) throws Exception {
        return send(INS_UPDATE_META, slot, 0, metaTlv, false);
    }

    public Resp setPassword(int slot, byte[] password) throws Exception {
        return send(INS_SET_PASSWORD, slot, 0, password, false);
    }

    public Resp getMeta(int slot) throws Exception {
        return send(INS_GET_META, slot, 0, null, true);
    }

    public Resp getPassword(int slot) throws Exception {
        return send(INS_GET_PASSWORD, slot, 0, null, true);
    }

    public Resp deleteEntry(int slot) throws Exception {
        return send(INS_DELETE_ENTRY, slot, 0, null, false);
    }

    public Resp search(int groupP1, String keyword) throws Exception {
        return send(INS_SEARCH, groupP1, 0, keyword.getBytes(StandardCharsets.UTF_8), true);
    }

    public Resp genPassword(int length, int flags) throws Exception {
        return send(INS_GEN_PASSWORD, length, flags, null, true);
    }

    /** Bitmap 4 byte -> danh sách số ô (ô i: byte i/8, bit i%8). */
    public static java.util.List<Integer> slotsOf(byte[] bitmap) {
        java.util.List<Integer> r = new java.util.ArrayList<>();
        for (int i = 0; i < 32; i++) {
            if ((bitmap[i >> 3] & (1 << (i & 7))) != 0) {
                r.add(i);
            }
        }
        return r;
    }

    // ------------------------------------------------------------------ Mở rộng: sao lưu, khôi phục

    public static final int INS_BACKUP_BEGIN = 0x60;
    public static final int INS_BACKUP_READ = 0x61;
    public static final int INS_RESTORE_BEGIN = 0x62;
    public static final int INS_RESTORE_WRITE = 0x63;

    public Resp backupBegin(String passphrase) throws Exception {
        return send(INS_BACKUP_BEGIN, 0, 0, passphrase.getBytes(StandardCharsets.UTF_8), true);
    }

    /** part = 0 phần thông tin, 1 phần mật khẩu. */
    public Resp backupRead(int slot, int part) throws Exception {
        return send(INS_BACKUP_READ, slot, part, null, true);
    }

    public Resp restoreBegin(String passphrase, byte[] header) throws Exception {
        byte[] p = passphrase.getBytes(StandardCharsets.UTF_8);
        return send(INS_RESTORE_BEGIN, 0, 0, join(new byte[] { (byte) p.length }, p, header), false);
    }

    public Resp restoreWrite(int slot, int part, byte[] blob) throws Exception {
        return send(INS_RESTORE_WRITE, slot, part, blob, false);
    }

    /** Sao lưu toàn bộ két: BACKUP_BEGIN rồi BACKUP_READ từng ô đang có dữ liệu. */
    public BackupFile backup(String passphrase) throws Exception {
        byte[] header = require(backupBegin(passphrase)).data();
        BackupFile f = new BackupFile(header);
        for (int slot : slotsOf(require(listSlots()).data())) {
            byte[] meta = require(backupRead(slot, 0)).data();
            Resp pw = backupRead(slot, 1);
            f.add(slot, meta, pw.sw() == 0x6A88 ? null : require(pw).data());
        }
        return f;
    }

    /** Khôi phục: RESTORE_BEGIN rồi RESTORE_WRITE từng ô (thông tin trước, mật khẩu sau). */
    public void restore(String passphrase, BackupFile f) throws Exception {
        require(restoreBegin(passphrase, f.header()));
        for (BackupFile.Entry e : f.entries()) {
            require(restoreWrite(e.slot(), 0, e.meta()));
            if (e.password() != null) {
                require(restoreWrite(e.slot(), 1, e.password()));
            }
        }
    }

    // ------------------------------------------------------------------ Giai đoạn 4: admin

    public static final int INS_ADMIN_CHALLENGE = 0x70;
    public static final int INS_ADMIN_AUTH = 0x71;
    public static final int INS_ADMIN_LOCK = 0x72;
    public static final int INS_REVOKE = 0x73;

    public Resp adminChallenge() throws Exception {
        return send(INS_ADMIN_CHALLENGE, 0, 0, null, true);
    }

    public Resp adminAuth(byte[] response) throws Exception {
        return send(INS_ADMIN_AUTH, 0, 0, response, false);
    }

    public Resp adminLock(boolean lock) throws Exception {
        return send(INS_ADMIN_LOCK, lock ? 1 : 0, 0, null, false);
    }

    public Resp revoke() throws Exception {
        return send(INS_REVOKE, 0, 0, null, false);
    }

    /** Phản hồi admin = AES-128-CBC(adminKey, IV = 0, challenge) = AES-ECB vì chỉ có 1 khối. */
    public static byte[] adminResponse(byte[] adminKey, byte[] challenge) throws Exception {
        javax.crypto.Cipher c = javax.crypto.Cipher.getInstance("AES/ECB/NoPadding");
        c.init(javax.crypto.Cipher.ENCRYPT_MODE, new javax.crypto.spec.SecretKeySpec(adminKey, "AES"));
        return c.doFinal(challenge);
    }

    /** ADMIN_CHALLENGE rồi ADMIN_AUTH ngay sau đó. */
    public Resp adminLogin(byte[] adminKey) throws Exception {
        byte[] ch = require(adminChallenge()).data();
        return adminAuth(adminResponse(adminKey, ch));
    }

    // ------------------------------------------------------------------ TLV

    public static byte[] tlv(int tag, byte[] value) {
        byte[] r = new byte[2 + value.length];
        r[0] = (byte) tag;
        r[1] = (byte) value.length;
        System.arraycopy(value, 0, r, 2, value.length);
        return r;
    }

    public static byte[] tlv(int tag, String value) {
        return tlv(tag, value.getBytes(StandardCharsets.UTF_8));
    }

    public static byte[] join(byte[]... parts) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] p : parts) {
            out.writeBytes(p);
        }
        return out.toByteArray();
    }

    // ------------------------------------------------------------------ Tiện ích

    public static Resp require(Resp r) {
        if (!r.ok()) {
            throw new IllegalStateException("Thẻ trả lỗi " + String.format("%04X", r.sw()));
        }
        return r;
    }

    static byte[] ascii(String s) {
        return s.getBytes(StandardCharsets.US_ASCII);
    }

    /** Mã hoá dạng độ dài | dữ liệu. */
    static byte[] lv(String s) {
        byte[] b = ascii(s);
        return concat(new byte[] { (byte) b.length }, b);
    }

    static byte[] concat(byte[] a, byte[] b) {
        byte[] r = new byte[a.length + b.length];
        System.arraycopy(a, 0, r, 0, a.length);
        System.arraycopy(b, 0, r, a.length, b.length);
        return r;
    }
}
