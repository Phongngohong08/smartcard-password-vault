package vault.tester;

import static vault.tester.Check.*;
import static vault.tester.VaultCard.*;

import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/** Giai đoạn 3: két mật khẩu, tìm kiếm, sinh mật khẩu. */
public class Stage3Test {

    static byte[] meta(String service, String url, String user, String note, int group) {
        return join(tlv(TAG_SERVICE, service), tlv(TAG_URL, url), tlv(TAG_USERNAME, user),
                tlv(TAG_NOTE, note), tlv(TAG_GROUP, new byte[] { (byte) group }));
    }

    static byte[] pw(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }

    static List<Integer> slots(Resp r) {
        return r.ok() ? slotsOf(r.data()) : List.of(-1);
    }

    static void run(VaultCard vc) throws Exception {
        Fixture.issueAndLogin(vc);

        section("Két rỗng, dữ liệu sai");
        expectData("LIST_SLOTS = 00000000", vc.listSlots(), new byte[4]);
        expectSw("Thiếu tên dịch vụ -> 6A80", vc.addEntry(tlv(TAG_URL, "x.com")), 0x6A80);
        expectSw("Không có dữ liệu -> 6A80", vc.addEntry(new byte[0]), 0x6A80);
        expectSw("Tên dịch vụ 33 byte -> 6A80", vc.addEntry(tlv(TAG_SERVICE, "S".repeat(33))), 0x6A80);
        expectSw("URL 65 byte -> 6A80",
                vc.addEntry(join(tlv(TAG_SERVICE, "A"), tlv(TAG_URL, "u".repeat(65)))), 0x6A80);
        expectSw("Nhóm = 6 -> 6A80",
                vc.addEntry(join(tlv(TAG_SERVICE, "A"), tlv(TAG_GROUP, new byte[] { 6 }))), 0x6A80);
        expectSw("Nhóm dài 2 byte -> 6A80",
                vc.addEntry(join(tlv(TAG_SERVICE, "A"), tlv(TAG_GROUP, new byte[] { 1, 1 }))), 0x6A80);
        expectSw("Tag lạ 0x15 -> 6A80", vc.addEntry(join(tlv(TAG_SERVICE, "A"), tlv(0x15, "x"))), 0x6A80);
        expectData("Két vẫn rỗng", vc.listSlots(), new byte[4]);

        section("ADD_ENTRY / GET_META");
        byte[][] metas = {
                meta("Gmail", "https://mail.google.com", "an.nguyen@gmail.com", "Email chính", GROUP_EMAIL),
                meta("Facebook", "https://facebook.com", "an.nguyen", "", GROUP_SOCIAL),
                meta("Vietcombank", "https://vcbdigibank.vietcombank.com.vn", "0123456789", "Smart OTP", GROUP_BANK),
                meta("Jira công ty", "https://jira.example.com", "an.nv", "VPN trước", GROUP_WORK),
                meta("Shopee", "https://shopee.vn", "an_shop", "", GROUP_SHOPPING),
                join(tlv(TAG_SERVICE, "Wifi nhà")), // không có nhóm -> "khác"
        };
        // ghi chú rỗng không hợp lệ (min 1) -> bỏ trường rỗng
        for (int i = 0; i < metas.length; i++) {
            metas[i] = stripEmpty(metas[i]);
            expectData("Thêm bản ghi -> ô " + i, vc.addEntry(metas[i]), new byte[] { (byte) i });
        }
        expectData("LIST_SLOTS = 3F000000 (ô 0-5)", vc.listSlots(), new byte[] { 0x3F, 0, 0, 0 });
        expectData("GET_META ô 0 đúng", vc.getMeta(0), metas[0]);
        expectData("GET_META ô 3 (tiếng Việt) đúng", vc.getMeta(3), metas[3]);
        byte[] maxMeta = join(tlv(TAG_SERVICE, "S".repeat(32)), tlv(TAG_URL, "u".repeat(64)),
                tlv(TAG_USERNAME, "n".repeat(48)), tlv(TAG_NOTE, "g".repeat(48)), tlv(TAG_GROUP, new byte[] { 0 }));
        expectData("Bản ghi tối đa (" + maxMeta.length + " byte) -> ô 6", vc.addEntry(maxMeta), new byte[] { 6 });
        expectData("Đọc lại bản ghi tối đa", vc.getMeta(6), maxMeta);
        expectSw("GET_META ô trống 7 -> 6A88", vc.getMeta(7), 0x6A88);
        expectSw("GET_META ô 32 -> 6A86", vc.getMeta(32), 0x6A86);

        section("SET_PASSWORD / GET_PASSWORD");
        expectSw("Chưa đặt mật khẩu -> 6A88", vc.getPassword(0), 0x6A88);
        byte[] gmailPw = pw("Gm@il-secretword-2026");
        expectSw("Đặt mật khẩu ô 0", vc.setPassword(0, gmailPw), 0x9000);
        expectData("Đọc lại mật khẩu ô 0", vc.getPassword(0), gmailPw);
        byte[] pw64 = pw("P".repeat(64));
        expectSw("Mật khẩu 64 byte", vc.setPassword(1, pw64), 0x9000);
        expectData("Đọc lại mật khẩu 64 byte", vc.getPassword(1), pw64);
        expectSw("Mật khẩu 65 byte -> 6700", vc.setPassword(1, pw("P".repeat(65))), 0x6700);
        expectSw("Mật khẩu rỗng -> 6700", vc.setPassword(1, new byte[0]), 0x6700);
        expectSw("Ô trống 7 -> 6A88", vc.setPassword(7, gmailPw), 0x6A88);
        expectSw("Ô 40 -> 6A86", vc.setPassword(40, gmailPw), 0x6A86);
        byte[] bankPw = pw("Vcb#123456");
        VaultCard.require(vc.setPassword(2, bankPw));
        byte[] newGmail = pw("doi-mat-khau-moi!");
        expectSw("Đổi mật khẩu ô 0", vc.setPassword(0, newGmail), 0x9000);
        expectData("Mật khẩu mới ô 0", vc.getPassword(0), newGmail);

        section("UPDATE_META");
        byte[] fbNew = meta("Facebook", "https://facebook.com", "an.nguyen.2026", "Đổi tên đăng nhập", GROUP_SOCIAL);
        expectSw("Sửa thông tin ô 1", vc.updateMeta(1, fbNew), 0x9000);
        expectData("Thông tin mới ô 1", vc.getMeta(1), fbNew);
        expectData("Mật khẩu ô 1 không đổi", vc.getPassword(1), pw64);
        expectSw("Sửa ô trống 7 -> 6A88", vc.updateMeta(7, fbNew), 0x6A88);
        expectSw("Sửa với TLV thiếu dịch vụ -> 6A80", vc.updateMeta(1, tlv(TAG_URL, "x")), 0x6A80);
        expectData("Thông tin ô 1 giữ nguyên sau lệnh lỗi", vc.getMeta(1), fbNew);

        section("SEARCH");
        check("'GMAIL' (khác hoa thường) -> ô 0", slots(vc.search(0, "GMAIL")).equals(List.of(0)),
                slots(vc.search(0, "GMAIL")).toString());
        check("'google' (trong URL) -> ô 0", slots(vc.search(0, "google")).equals(List.of(0)), "");
        check("'an.nguyen' (tên đăng nhập) -> ô 0, 1",
                slots(vc.search(0, "an.nguyen")).equals(List.of(0, 1)), slots(vc.search(0, "an.nguyen")).toString());
        check("'https' -> ô 0-4", slots(vc.search(0, "https")).equals(List.of(0, 1, 2, 3, 4)), "");
        check("'công ty' (UTF-8) -> ô 3", slots(vc.search(0, "công ty")).equals(List.of(3)), "");
        check("'secretword' chỉ có trong mật khẩu cũ -> không thấy", slots(vc.search(0, "secretword")).isEmpty(), "");
        check("'Smart OTP' chỉ có trong ghi chú -> không thấy", slots(vc.search(0, "Smart OTP")).isEmpty(), "");
        check("'doi-mat-khau' (mật khẩu hiện tại) -> không thấy", slots(vc.search(0, "doi-mat-khau")).isEmpty(), "");
        check("Từ khoá rỗng, mọi nhóm -> tất cả ô", slots(vc.search(0, "")).equals(List.of(0, 1, 2, 3, 4, 5, 6)), "");
        check("Nhóm ngân hàng (3) -> ô 2", slots(vc.search(GROUP_BANK, "")).equals(List.of(2)), "");
        check("Nhóm mạng xã hội + 'face' -> ô 1", slots(vc.search(GROUP_SOCIAL, "face")).equals(List.of(1)), "");
        check("Nhóm email + 'face' -> không có", slots(vc.search(GROUP_EMAIL, "face")).isEmpty(), "");
        check("Nhóm 'khác' (P1 = 0x80) -> ô 5, 6",
                slots(vc.search(SEARCH_GROUP_OTHER, "")).equals(List.of(5, 6)),
                slots(vc.search(SEARCH_GROUP_OTHER, "")).toString());
        expectSw("Nhóm 6 -> 6A86", vc.search(6, ""), 0x6A86);
        expectSw("Từ khoá 33 byte -> 6700", vc.search(0, "k".repeat(33)), 0x6700);

        section("DELETE_ENTRY");
        expectSw("Xoá ô 2", vc.deleteEntry(2), 0x9000);
        expectData("LIST_SLOTS = 7B000000 (không còn ô 2)", vc.listSlots(), new byte[] { 0x7B, 0, 0, 0 });
        expectSw("GET_META ô 2 -> 6A88", vc.getMeta(2), 0x6A88);
        expectSw("GET_PASSWORD ô 2 -> 6A88", vc.getPassword(2), 0x6A88);
        expectSw("Xoá lại ô 2 -> 6A88", vc.deleteEntry(2), 0x6A88);
        check("Tìm 'vietcombank' -> không còn", slots(vc.search(0, "vietcombank")).isEmpty(), "");
        expectData("Thêm mới dùng lại ô 2", vc.addEntry(metas[2]), new byte[] { 2 });
        expectSw("Ô 2 mới chưa có mật khẩu (không lộ mật khẩu cũ)", vc.getPassword(2), 0x6A88);

        section("Két đầy");
        int added = 0;
        while (true) {
            Resp r = vc.addEntry(tlv(TAG_SERVICE, "Dịch vụ " + added));
            if (!r.ok()) {
                expectSw("Ô thứ 33 -> 6A84", r, 0x6A84);
                break;
            }
            added++;
        }
        check("Thêm được thêm " + added + " ô (tổng 32)", added == 32 - 7, "added=" + added);
        expectData("LIST_SLOTS = FFFFFFFF", vc.listSlots(), new byte[] { -1, -1, -1, -1 });
        expectData("Ô 31 đọc được", vc.getMeta(31), tlv(TAG_SERVICE, "Dịch vụ 24"));

        section("Master Key giữ nguyên sau đổi PIN");
        VaultCard.require(vc.changePin(Fixture.PIN, "pin-moi-1"));
        VaultCard.require(vc.logout());
        expectSw("Sau LOGOUT -> LIST_SLOTS 6982", vc.listSlots(), 0x6982);
        expectSw("Sau LOGOUT -> GET_PASSWORD 6982", vc.getPassword(0), 0x6982);
        VaultCard.require(vc.verifyPin("pin-moi-1"));
        expectData("Mật khẩu ô 0 vẫn đúng", vc.getPassword(0), newGmail);
        expectData("Thông tin ô 3 vẫn đúng", vc.getMeta(3), metas[3]);

        section("GEN_PASSWORD");
        VaultCard.require(vc.logout());
        Resp g = vc.genPassword(16, 0x0F);
        expectSw("Không cần PIN, 16 ký tự, đủ 4 loại", g, 0x9000);
        String p = new String(g.data(), StandardCharsets.US_ASCII);
        check("Dài 16, có thường/hoa/số/ký hiệu: " + p,
                p.length() == 16 && p.matches(".*[a-z].*") && p.matches(".*[A-Z].*")
                        && p.matches(".*[0-9].*") && p.matches(".*[^a-zA-Z0-9].*"), p);
        String digits = new String(vc.genPassword(8, GEN_DIGIT).data(), StandardCharsets.US_ASCII);
        check("Chỉ số, 8 ký tự: " + digits, digits.matches("[0-9]{8}"), digits);
        String lu = new String(vc.genPassword(64, GEN_LOWER | GEN_UPPER).data(), StandardCharsets.US_ASCII);
        check("64 ký tự chữ thường + hoa", lu.matches("[a-zA-Z]{64}") && lu.matches(".*[a-z].*")
                && lu.matches(".*[A-Z].*"), lu);
        String sym = new String(vc.genPassword(12, GEN_SYMBOL).data(), StandardCharsets.US_ASCII);
        check("Chỉ ký hiệu: " + sym, sym.matches("[!@#$%^&*()\\-_=+\\[\\]{};:,.?/]{12}"), sym);
        Set<String> seen = new HashSet<>();
        for (int i = 0; i < 20; i++) {
            seen.add(new String(vc.genPassword(12, 0x0F).data(), StandardCharsets.US_ASCII));
        }
        check("20 lần sinh -> 20 mật khẩu khác nhau", seen.size() == 20, seen.size() + "");
        expectSw("Độ dài 7 -> 6A86", vc.genPassword(7, 0x0F), 0x6A86);
        expectSw("Độ dài 65 -> 6A86", vc.genPassword(65, 0x0F), 0x6A86);
        expectSw("Không chọn loại nào -> 6A86", vc.genPassword(16, 0), 0x6A86);
        expectSw("Cờ không hợp lệ 0x10 -> 6A86", vc.genPassword(16, 0x10), 0x6A86);

        // Kiểm tra phân phối thô: mọi chữ số đều xuất hiện, không chữ số nào áp đảo
        int[] count = new int[10];
        for (int i = 0; i < 25; i++) {
            for (byte b : vc.genPassword(64, GEN_DIGIT).data()) {
                count[b - '0']++;
            }
        }
        int min = Integer.MAX_VALUE, max = 0;
        for (int c : count) {
            min = Math.min(min, c);
            max = Math.max(max, c);
        }
        check("1600 chữ số: mỗi số xuất hiện 110-210 lần (kỳ vọng 160)", min >= 110 && max <= 210,
                java.util.Arrays.toString(count));
    }

    /** Bỏ các trường TLV rỗng (applet không nhận trường dài 0). */
    static byte[] stripEmpty(byte[] tlvs) {
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        for (int i = 0; i < tlvs.length;) {
            int len = tlvs[i + 1] & 0xFF;
            if (len > 0) {
                out.write(tlvs, i, 2 + len);
            }
            i += 2 + len;
        }
        return out.toByteArray();
    }
}
