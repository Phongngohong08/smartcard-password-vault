package vault.tester;

import static vault.tester.Check.*;
import static vault.tester.VaultCard.*;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Mở rộng (giai đoạn 6 trong kế hoạch): sao lưu ở thẻ A, rồi khôi phục sang thẻ B mới phát hành.
 * Hai "thẻ" được giả lập bằng cách nạp lại applet ở giữa.
 */
public class Stage6Test {

    static final String PASS = "correct horse battery";

    static void run(VaultCard vc) throws Exception {
        // ================= THẺ A =================
        Fixture.issueAndLogin(vc);
        VaultCard.require(vc.logout());

        section("Thẻ A - điều kiện");
        expectSw("BACKUP_BEGIN khi chưa có PIN -> 6982", vc.backupBegin(PASS), 0x6982);
        VaultCard.require(vc.verifyPin(Fixture.PIN));
        expectSw("BACKUP_READ khi chưa BACKUP_BEGIN -> 6985", vc.backupRead(0, 0), 0x6985);
        expectSw("Passphrase 7 byte -> 6A80", vc.backupBegin("1234567"), 0x6A80);
        expectSw("Passphrase 65 byte -> 6A80", vc.backupBegin("p".repeat(65)), 0x6A80);

        // Dữ liệu mẫu: ô 0, 2 có mật khẩu; ô 3 chưa có mật khẩu; ô 1 bị xoá (để có lỗ hổng)
        byte[][] metas = {
                join(tlv(TAG_SERVICE, "Gmail"), tlv(TAG_USERNAME, "an@gmail.com"), tlv(TAG_GROUP, new byte[] { 1 })),
                join(tlv(TAG_SERVICE, "Sẽ bị xoá")),
                join(tlv(TAG_SERVICE, "Vietcombank"), tlv(TAG_NOTE, "Smart OTP"), tlv(TAG_GROUP, new byte[] { 3 })),
                join(tlv(TAG_SERVICE, "Wifi nhà"), tlv(TAG_URL, "192.168.1.1")),
        };
        for (byte[] m : metas) {
            VaultCard.require(vc.addEntry(m));
        }
        VaultCard.require(vc.setPassword(0, "Gm@il-2026".getBytes()));
        VaultCard.require(vc.setPassword(1, "bi-xoa".getBytes()));
        VaultCard.require(vc.setPassword(2, "Vcb#123456".getBytes()));
        VaultCard.require(vc.deleteEntry(1));
        VaultCard.require(vc.setProfile(tlv(0x01, "Nguyễn Văn An")));
        Map<Integer, byte[][]> plainA = readPlain(vc);
        check("Thẻ A có ô 0, 2, 3", plainA.keySet().equals(java.util.Set.of(0, 2, 3)), plainA.keySet().toString());

        section("Thẻ A - BACKUP_BEGIN / BACKUP_READ");
        Resp h1 = vc.backupBegin(PASS);
        expectSw("BACKUP_BEGIN", h1, 0x9000);
        check("Phần đầu dài 48 byte", h1.data().length == 48, h1.toString());
        byte[] h2 = vc.backupBegin(PASS).data();
        check("Mỗi lần sao lưu một salt mới", !Arrays.equals(Arrays.copyOf(h1.data(), 16), Arrays.copyOf(h2, 16)), "");
        expectSw("Ô trống 1 -> 6A88", vc.backupRead(1, 0), 0x6A88);
        expectSw("Ô 3 chưa có mật khẩu -> 6A88", vc.backupRead(3, 1), 0x6A88);
        expectSw("Ô 32 -> 6A86", vc.backupRead(32, 0), 0x6A86);
        expectSw("P2 = 2 -> 6A86", vc.backupRead(0, 2), 0x6A86);
        Resp raw = vc.backupRead(0, 1);
        check("Blob mật khẩu là IV | ciphertext (bội số 16, ≥ 32 byte)",
                raw.ok() && raw.data().length >= 32 && raw.data().length % 16 == 0, raw.toString());
        check("Blob không chứa mật khẩu rõ",
                !new String(raw.data(), StandardCharsets.ISO_8859_1).contains("Gm@il"), "");

        BackupFile backup = vc.backup(PASS);
        byte[] file = backup.toBytes();
        System.out.printf("   (file sao lưu %d byte, %d bản ghi)%n", file.length, backup.entries().size());
        check("File sao lưu có 3 bản ghi (ô 0, 2, 3)", backup.entries().size() == 3, "");
        BackupFile parsed = BackupFile.parse(file);
        check("Đọc lại file sao lưu cho ra đúng nội dung", Arrays.equals(parsed.toBytes(), file), "");

        VaultCard.require(vc.logout());
        expectSw("Sau LOGOUT -> BACKUP_READ 6982", vc.backupRead(0, 0), 0x6982);
        VaultCard.require(vc.verifyPin(Fixture.PIN));
        expectSw("Đăng nhập lại nhưng chưa BACKUP_BEGIN -> 6985", vc.backupRead(0, 0), 0x6985);

        // ================= THẺ B (thẻ mới thay thế) =================
        Fixture.redeploy.run();
        VaultCard.require(vc.select());
        VaultCard.require(vc.issue("SC000002", "654321", "87654321", Fixture.ADMIN_KEY));

        section("Thẻ B - RESTORE_BEGIN");
        expectSw("RESTORE_BEGIN khi chưa có PIN -> 6982", vc.restoreBegin(PASS, parsed.header()), 0x6982);
        VaultCard.require(vc.verifyPin("654321"));
        expectData("Thẻ B mới: két rỗng", vc.listSlots(), new byte[4]);
        expectSw("RESTORE_WRITE khi chưa RESTORE_BEGIN -> 6985",
                vc.restoreWrite(0, 0, parsed.entries().get(0).meta()), 0x6985);
        expectSw("Sai passphrase -> 6300", vc.restoreBegin("wrong horse battery", parsed.header()), 0x6300);
        expectSw("Sau khi sai, RESTORE_WRITE -> 6985",
                vc.restoreWrite(0, 0, parsed.entries().get(0).meta()), 0x6985);
        byte[] badHeader = parsed.header();
        badHeader[20] ^= 1;
        expectSw("Phần đầu bị sửa 1 bit -> 6300", vc.restoreBegin(PASS, badHeader), 0x6300);
        expectSw("Thiếu 1 byte phần đầu -> 6700",
                vc.restoreBegin(PASS, Arrays.copyOf(parsed.header(), 47)), 0x6700);
        expectSw("Passphrase ngắn -> 6A80", vc.restoreBegin("short", parsed.header()), 0x6A80);
        expectSw("Đúng passphrase -> 9000", vc.restoreBegin(PASS, parsed.header()), 0x9000);

        section("Thẻ B - RESTORE_WRITE: lỗi");
        BackupFile.Entry e0 = parsed.entries().get(0);
        expectSw("Ghi mật khẩu trước thông tin -> 6A88", vc.restoreWrite(0, 1, e0.password()), 0x6A88);
        expectSw("Blob 31 byte -> 6700", vc.restoreWrite(0, 0, Arrays.copyOf(e0.meta(), 31)), 0x6700);
        expectSw("Blob 16 byte (chỉ IV) -> 6700", vc.restoreWrite(0, 0, Arrays.copyOf(e0.meta(), 16)), 0x6700);
        expectSw("Ô 32 -> 6A86", vc.restoreWrite(32, 0, e0.meta()), 0x6A86);
        expectSw("P2 = 2 -> 6A86", vc.restoreWrite(0, 2, e0.meta()), 0x6A86);
        byte[] tampered = e0.meta().clone();
        tampered[tampered.length - 1] ^= 0x55;
        Resp t = vc.restoreWrite(0, 0, tampered);
        check("Blob bị sửa -> bị từ chối (6984 padding hỏng / 6A80 TLV hỏng)",
                t.sw() == 0x6984 || t.sw() == 0x6A80, t.toString());
        expectData("Không ô nào được ghi", vc.listSlots(), new byte[4]);

        section("Thẻ B - khôi phục toàn bộ");
        for (BackupFile.Entry e : parsed.entries()) {
            expectSw("Thông tin ô " + e.slot(), vc.restoreWrite(e.slot(), 0, e.meta()), 0x9000);
            if (e.password() != null) {
                expectSw("Mật khẩu ô " + e.slot(), vc.restoreWrite(e.slot(), 1, e.password()), 0x9000);
            }
        }
        Map<Integer, byte[][]> plainB = readPlain(vc);
        check("Thẻ B có đúng các ô 0, 2, 3", plainB.keySet().equals(plainA.keySet()), plainB.keySet().toString());
        for (int slot : plainA.keySet()) {
            check("Ô " + slot + ": thông tin giống thẻ A", Arrays.equals(plainA.get(slot)[0], plainB.get(slot)[0]), "");
            check("Ô " + slot + ": mật khẩu giống thẻ A", Arrays.equals(plainA.get(slot)[1], plainB.get(slot)[1]), "");
        }
        check("Tìm kiếm trên thẻ B: 'vietcom' -> ô 2",
                slotsOf(vc.search(0, "vietcom").data()).equals(List.of(2)), "");
        expectSw("Hồ sơ không nằm trong bản sao lưu -> 6A88", vc.getProfile(), 0x6A88);

        section("Thẻ B - dữ liệu đã được mã hoá lại bằng MK của thẻ B");
        BackupFile backupB = vc.backup("another passphrase");
        expectSw("File sao lưu thẻ A không mở được bằng passphrase của B",
                vc.restoreBegin("another passphrase", parsed.header()), 0x6300);
        byte[] headerB = backupB.header();
        check("Giá trị kiểm tra AES(MK, hằng số) khác nhau -> MK thẻ B ≠ MK thẻ A",
                !Arrays.equals(Arrays.copyOfRange(headerB, 32, 48), Arrays.copyOfRange(parsed.header(), 32, 48)), "");
        VaultCard.require(vc.restoreBegin(PASS, parsed.header()));
        expectSw("Blob cũ của thẻ A vẫn ghi đè được ô 3", vc.restoreWrite(3, 0, parsed.entries().get(2).meta()),
                0x9000);
        expectSw("Ghi đè thông tin thì ô 3 chưa có mật khẩu", vc.getPassword(3), 0x6A88);

        VaultCard.require(vc.select());
        expectSw("Sau deselect, MK cũ bị xoá -> RESTORE_WRITE 6982", vc.restoreWrite(0, 0, e0.meta()), 0x6982);
        VaultCard.require(vc.verifyPin("654321"));
        expectSw("Đăng nhập lại -> RESTORE_WRITE 6985", vc.restoreWrite(0, 0, e0.meta()), 0x6985);

        section("Thẻ B - đổi PIN rồi khôi phục vẫn đúng");
        VaultCard.require(vc.changePin("654321", "pin-B-moi"));
        VaultCard.require(vc.logout());
        VaultCard.require(vc.verifyPin("pin-B-moi"));
        expectData("Mật khẩu ô 2 vẫn đúng", vc.getPassword(2), plainA.get(2)[1]);
    }

    /** Đọc bản rõ của mọi ô: {thông tin, mật khẩu (null nếu chưa có)}. */
    static Map<Integer, byte[][]> readPlain(VaultCard vc) throws Exception {
        Map<Integer, byte[][]> m = new LinkedHashMap<>();
        for (int slot : slotsOf(VaultCard.require(vc.listSlots()).data())) {
            byte[] meta = VaultCard.require(vc.getMeta(slot)).data();
            Resp pw = vc.getPassword(slot);
            m.put(slot, new byte[][] { meta, pw.ok() ? pw.data() : null });
        }
        return m;
    }
}
