package vault.tester;

import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * File sao lưu két (lưu vào cột backups.data). Mọi blob giữ nguyên dạng đã mã hoá trên thẻ.
 *
 * Định dạng nhị phân:
 *   "VBK1" (4) | header (48) | số bản ghi (1) |
 *   mỗi bản ghi: ô (1) | lenMeta (1) | meta | lenPw (1, 0 = chưa có mật khẩu) | pw
 *
 * header = backupSalt(16) | AES(BK, MK)(16) | AES(MK, "VAULTBACKUPCHECK")(16)
 */
public final class BackupFile {

    public record Entry(int slot, byte[] meta, byte[] password) {}

    private static final byte[] MAGIC = { 'V', 'B', 'K', '1' };
    public static final int HEADER_LEN = 48;

    private final byte[] header;
    private final List<Entry> entries = new ArrayList<>();

    public BackupFile(byte[] header) {
        if (header.length != HEADER_LEN) {
            throw new IllegalArgumentException("Header phải dài 48 byte");
        }
        this.header = header.clone();
    }

    public void add(int slot, byte[] meta, byte[] password) {
        entries.add(new Entry(slot, meta, password));
    }

    public byte[] header() {
        return header.clone();
    }

    public List<Entry> entries() {
        return entries;
    }

    public byte[] toBytes() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.writeBytes(MAGIC);
        out.writeBytes(header);
        out.write(entries.size());
        for (Entry e : entries) {
            out.write(e.slot());
            out.write(e.meta().length);
            out.writeBytes(e.meta());
            byte[] pw = e.password() == null ? new byte[0] : e.password();
            out.write(pw.length);
            out.writeBytes(pw);
        }
        return out.toByteArray();
    }

    public static BackupFile parse(byte[] b) {
        if (b.length < 4 + HEADER_LEN + 1 || !Arrays.equals(Arrays.copyOf(b, 4), MAGIC)) {
            throw new IllegalArgumentException("Không phải file sao lưu VBK1");
        }
        int p = 4;
        BackupFile f = new BackupFile(Arrays.copyOfRange(b, p, p + HEADER_LEN));
        p += HEADER_LEN;
        int count = b[p++] & 0xFF;
        for (int i = 0; i < count; i++) {
            int slot = b[p++] & 0xFF;
            int ml = b[p++] & 0xFF;
            byte[] meta = Arrays.copyOfRange(b, p, p + ml);
            p += ml;
            int pl = b[p++] & 0xFF;
            byte[] pw = pl == 0 ? null : Arrays.copyOfRange(b, p, p + pl);
            p += pl;
            f.add(slot, meta, pw);
        }
        if (p != b.length) {
            throw new IllegalArgumentException("Thừa dữ liệu cuối file");
        }
        return f;
    }
}
