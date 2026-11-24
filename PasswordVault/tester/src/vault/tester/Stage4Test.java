package vault.tester;

import static vault.tester.Check.*;
import static vault.tester.VaultCard.*;

import java.util.Arrays;

import vault.tester.VaultCard.Status;

/** Giai đoạn 4: admin xác thực, khoá / mở khoá, thu hồi. */
public class Stage4Test {

    static void run(VaultCard vc) throws Exception {
        Fixture.issueAndLogin(vc);
        byte[] entry = tlv(TAG_SERVICE, "Gmail");
        byte[] secret = "mat-khau-bi-mat".getBytes();
        VaultCard.require(vc.addEntry(entry));
        VaultCard.require(vc.setPassword(0, secret));
        byte[] key = Fixture.ADMIN_KEY;

        section("Chưa xác thực admin");
        expectSw("ADMIN_LOCK -> 6982", vc.adminLock(true), 0x6982);
        expectSw("REVOKE -> 6982", vc.revoke(), 0x6982);
        expectSw("ADMIN_AUTH khi chưa có challenge -> 6985", vc.adminAuth(new byte[16]), 0x6985);
        expectSw("Phiên PIN không thay được admin: ADMIN_LOCK -> 6982", vc.adminLock(true), 0x6982);

        section("ADMIN_CHALLENGE / ADMIN_AUTH");
        Resp c1 = vc.adminChallenge();
        expectSw("ADMIN_CHALLENGE", c1, 0x9000);
        check("Challenge dài 16 byte", c1.data().length == 16, c1.toString());
        byte[] c2 = vc.adminChallenge().data();
        check("Mỗi lần một challenge khác", !Arrays.equals(c1.data(), c2), "");
        expectSw("Trả lời challenge cũ -> 6982", vc.adminAuth(adminResponse(key, c1.data())), 0x6982);
        expectSw("Challenge đã dùng (dù sai) -> lần sau 6985", vc.adminAuth(adminResponse(key, c2)), 0x6985);

        byte[] wrongKey = random(16);
        expectSw("Sai adminKey -> 6982", vc.adminLogin(wrongKey), 0x6982);
        expectSw("Vẫn chưa xác thực -> ADMIN_LOCK 6982", vc.adminLock(true), 0x6982);

        byte[] c3 = vc.adminChallenge().data();
        VaultCard.require(vc.getStatusRaw());
        expectSw("Có lệnh khác chen giữa challenge và auth -> 6985", vc.adminAuth(adminResponse(key, c3)), 0x6985);
        expectSw("Phản hồi 15 byte -> 6700", vcAuthShort(vc), 0x6700);

        expectSw("Đúng adminKey -> 9000", vc.adminLogin(key), 0x9000);

        section("ADMIN_LOCK");
        expectSw("P1 = 2 -> 6A86", vc.send(INS_ADMIN_LOCK, 2, 0, null, false), 0x6A86);
        expectSw("Mở khoá thẻ đang Hoạt động -> 9000 (không đổi)", vc.adminLock(false), 0x9000);
        expectSw("Khoá thẻ", vc.adminLock(true), 0x9000);
        Status st = vc.getStatus();
        check("Trạng thái = Khoá admin (03)", st.state() == STATE_ADMIN_LOCKED, st.toString());
        expectSw("Khoá lần nữa -> 9000 (không đổi)", vc.adminLock(true), 0x9000);
        expectSw("Phiên PIN bị huỷ -> GET_PASSWORD 6985", vc.getPassword(0), 0x6985);
        expectSw("VERIFY_PIN -> 6985", vc.verifyPin(Fixture.PIN), 0x6985);
        expectSw("CHANGE_PIN -> 6985", vc.changePin(Fixture.PIN, "999999"), 0x6985);
        expectSw("UNBLOCK_PUK -> 6985", vc.unblockPuk(Fixture.PUK, "999999"), 0x6985);
        expectSw("GEN_PASSWORD -> 6985", vc.genPassword(16, 0x0F), 0x6985);
        expectSw("INTERNAL_AUTH vẫn được (để phần mềm nhận ra thẻ)", vc.internalAuth(random(32)), 0x9000);

        VaultCard.require(vc.select());
        expectSw("SELECT lại -> phiên admin mất, ADMIN_LOCK 6982", vc.adminLock(false), 0x6982);
        VaultCard.require(vc.adminLogin(key));
        expectSw("Thẻ đang khoá vẫn xác thực admin được, mở khoá", vc.adminLock(false), 0x9000);
        check("Trạng thái = Hoạt động (01)", vc.getStatus().state() == STATE_ACTIVE, "");
        expectSw("Phiên admin không mở được két -> LIST_SLOTS 6982", vc.listSlots(), 0x6982);
        VaultCard.require(vc.verifyPin(Fixture.PIN));
        expectData("Dữ liệu còn nguyên sau khi mở khoá", vc.getPassword(0), secret);

        section("Không khoá được thẻ đang Khoá PIN");
        for (int i = 0; i < 3; i++) {
            vc.verifyPin("000000");
        }
        VaultCard.require(vc.adminLogin(key));
        expectSw("ADMIN_LOCK khi Khoá PIN -> 6985", vc.adminLock(true), 0x6985);
        expectSw("Mở khoá admin khi Khoá PIN -> 6985", vc.adminLock(false), 0x6985);
        check("Vẫn Khoá PIN (02)", vc.getStatus().state() == STATE_PIN_BLOCKED, "");
        VaultCard.require(vc.unblockPuk(Fixture.PUK, Fixture.PIN));

        section("REVOKE");
        VaultCard.require(vc.select());
        expectSw("REVOKE khi chưa xác thực -> 6982", vc.revoke(), 0x6982);
        VaultCard.require(vc.adminLogin(key));
        expectSw("REVOKE", vc.revoke(), 0x9000);
        st = vc.getStatus();
        check("Trạng thái = Thu hồi (04), mã thẻ còn đọc được",
                st.state() == STATE_REVOKED && st.cardId().equals(Fixture.CARD_ID), st.toString());
        expectSw("Phiên admin đã bị huỷ -> ADMIN_LOCK 6982", vc.adminLock(false), 0x6982);
        expectSw("ADMIN_CHALLENGE -> 6985", vc.adminChallenge(), 0x6985);
        expectSw("VERIFY_PIN -> 6985", vc.verifyPin(Fixture.PIN), 0x6985);
        expectSw("UNBLOCK_PUK -> 6985", vc.unblockPuk(Fixture.PUK, Fixture.PIN), 0x6985);
        expectSw("INTERNAL_AUTH -> 6985", vc.internalAuth(random(32)), 0x6985);
        expectSw("LIST_SLOTS -> 6985", vc.listSlots(), 0x6985);
        expectSw("GEN_PASSWORD -> 6985", vc.genPassword(16, 0x0F), 0x6985);
        expectSw("ISSUE lại -> 6985", vc.issue(Fixture.CARD_ID, Fixture.PIN, Fixture.PUK, key), 0x6985);
        expectSw("GET_PUBKEY vẫn đọc được", vc.getPubKeyPart(2), 0x9000);
    }

    /** Lấy challenge mới rồi gửi phản hồi chỉ 15 byte. */
    static Resp vcAuthShort(VaultCard vc) throws Exception {
        VaultCard.require(vc.adminChallenge());
        return vc.adminAuth(new byte[15]);
    }
}
