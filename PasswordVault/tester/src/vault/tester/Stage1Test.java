package vault.tester;

import static vault.tester.Check.*;

import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;

import vault.tester.VaultCard.Resp;
import vault.tester.VaultCard.Status;

/** Giai đoạn 1: phát hành, PIN/PUK, RSA. Chạy trên applet vừa nạp (thẻ trắng). */
public class Stage1Test {

    static final String CARD_ID = Fixture.CARD_ID;
    static final String PIN = Fixture.PIN;
    static final String PUK = Fixture.PUK;

    static void run(VaultCard vc) throws Exception {
        section("Chọn applet, lệnh cơ bản");
        expectSw("SELECT", vc.select(), 0x9000);
        Resp v = vc.getVersion();
        expectSw("GET_VERSION", v, 0x9000);
        check("Phiên bản = VAULT 1.0", new String(v.data()).equals("VAULT 1.0"), new String(v.data()));
        expectSw("CLA sai -> 6E00", vc.send(0x00, 0x11, 0, 0, null, true), 0x6E00);
        expectSw("INS lạ -> 6D00", vc.send(0x7F, 0, 0, null, false), 0x6D00);

        section("Trước khi phát hành");
        Status st = vc.getStatus();
        check("Trạng thái = Chưa phát hành (00)", st.state() == VaultCard.STATE_UNISSUED, st.toString());
        expectSw("VERIFY_PIN -> 6985", vc.verifyPin(PIN), 0x6985);
        expectSw("GET_PUBKEY -> 6985", vc.getPubKeyPart(0), 0x6985);
        expectSw("INTERNAL_AUTH -> 6985", vc.internalAuth(new byte[32]), 0x6985);

        section("ISSUE - dữ liệu sai");
        byte[] adminKey = random(16);
        expectSw("PIN 5 ký tự -> 6A80", vc.issue(CARD_ID, "12345", PUK, adminKey), 0x6A80);
        expectSw("PIN 13 ký tự -> 6A80", vc.issue(CARD_ID, "1234567890123", PUK, adminKey), 0x6A80);
        expectSw("PUK có chữ -> 6A80", vc.issue(CARD_ID, PIN, "1234567a", adminKey), 0x6A80);
        expectSw("PUK 7 số -> 6A80", vc.issue(CARD_ID, PIN, "1234567", adminKey), 0x6A80);
        expectSw("cardId chữ thường -> 6A80", vc.issue("sc000001", PIN, PUK, adminKey), 0x6A80);
        byte[] shortData = VaultCard.issueData(CARD_ID, PIN, PUK, new byte[15]);
        expectSw("adminKey 15 byte -> 6700", vc.send(VaultCard.INS_ISSUE, 0, 0, shortData, false), 0x6700);
        expectSw("Thiếu dữ liệu -> 6700", vc.send(VaultCard.INS_ISSUE, 0, 0, new byte[] { 'S', 'C' }, false), 0x6700);
        check("Vẫn Chưa phát hành", vc.getStatus().state() == VaultCard.STATE_UNISSUED, "");

        section("ISSUE hợp lệ");
        long t0 = System.currentTimeMillis();
        expectSw("ISSUE", vc.issue(CARD_ID, PIN, PUK, adminKey), 0x9000);
        System.out.printf("   (ISSUE mất %d ms, chủ yếu do sinh khoá RSA-2048)%n", System.currentTimeMillis() - t0);
        expectSw("ISSUE lần 2 -> 6985", vc.issue(CARD_ID, PIN, PUK, adminKey), 0x6985);
        st = vc.getStatus();
        check("GET_STATUS = 01 | SC000001 | 3 | 5",
                st.state() == 1 && st.cardId().equals(CARD_ID) && st.pinTriesLeft() == 3 && st.pukTriesLeft() == 5,
                st.toString());

        section("Khoá công khai và xác thực thẻ bằng RSA");
        RSAPublicKey pub = vc.getPublicKey();
        check("Modulus 2048 bit", pub.getModulus().bitLength() == 2048, pub.getModulus().bitLength() + " bit");
        check("Số mũ = 65537", pub.getPublicExponent().intValue() == 65537, pub.getPublicExponent().toString());
        expectSw("GET_PUBKEY P1=3 -> 6A86", vc.getPubKeyPart(3), 0x6A86);

        expectSw("GET_SIGNATURE trước INTERNAL_AUTH -> 6985", vc.getSignaturePart(0), 0x6985);
        expectSw("INTERNAL_AUTH challenge 31 byte -> 6700", vc.internalAuth(new byte[31]), 0x6700);
        byte[] ch = random(32);
        byte[] sig = vc.authenticate(ch);
        check("Chữ ký dài 256 byte", sig.length == 256, sig.length + "");
        check("Chữ ký hợp lệ (SHA256withRSA)", verifyRsa(pub, VaultCard.authMessage(CARD_ID, ch), sig), "");
        byte[] other = ch.clone();
        other[0] ^= 1;
        check("Đổi 1 bit challenge -> chữ ký không khớp", !verifyRsa(pub, VaultCard.authMessage(CARD_ID, other), sig), "");
        check("Ký thẳng challenge (không tiền tố) -> không khớp", !verifyRsa(pub, ch, sig), "");
        byte[] sig2 = vc.authenticate(random(32));
        check("Mỗi challenge cho chữ ký khác nhau", !Arrays.equals(sig, sig2), "");
        expectSw("SELECT lại", vc.select(), 0x9000);
        expectSw("Sau deselect, sigBuf bị xoá -> GET_SIGNATURE 6985", vc.getSignaturePart(0), 0x6985);

        section("VERIFY_PIN");
        expectSw("PIN sai -> 63C2", vc.verifyPin("000000"), 0x63C2);
        expectSw("PIN sai -> 63C1", vc.verifyPin("111111"), 0x63C1);
        expectSw("PIN đúng -> 9000", vc.verifyPin(PIN), 0x9000);
        check("Bộ đếm về lại 3", vc.getStatus().pinTriesLeft() == 3, "");
        expectSw("PIN quá ngắn -> 6A80 (không trừ lượt)", vc.verifyPin("123"), 0x6A80);
        check("Bộ đếm vẫn là 3", vc.getStatus().pinTriesLeft() == 3, "");
        expectSw("LOGOUT", vc.logout(), 0x9000);

        section("CHANGE_PIN");
        String pin2 = "Abc@1234";
        expectSw("PIN cũ sai -> 63C2", vc.changePin("999999", pin2), 0x63C2);
        expectSw("PIN mới quá ngắn -> 6A80", vc.changePin(PIN, "abc"), 0x6A80);
        expectSw("Đổi PIN", vc.changePin(PIN, pin2), 0x9000);
        check("Bộ đếm về lại 3", vc.getStatus().pinTriesLeft() == 3, "");
        expectSw("PIN cũ không còn dùng được -> 63C2", vc.verifyPin(PIN), 0x63C2);
        expectSw("PIN mới -> 9000", vc.verifyPin(pin2), 0x9000);

        section("Sai PIN 3 lần -> khoá PIN");
        expectSw("Sai lần 1 -> 63C2", vc.verifyPin("000000"), 0x63C2);
        expectSw("Sai lần 2 -> 63C1", vc.verifyPin("000000"), 0x63C1);
        expectSw("Sai lần 3 -> 6983", vc.verifyPin("000000"), 0x6983);
        st = vc.getStatus();
        check("Trạng thái = Khoá PIN (02), còn 0 lượt", st.state() == 2 && st.pinTriesLeft() == 0, st.toString());
        expectSw("PIN đúng cũng bị từ chối -> 6983", vc.verifyPin(pin2), 0x6983);
        expectSw("CHANGE_PIN -> 6983", vc.changePin(pin2, "newpin99"), 0x6983);
        expectSw("Thẻ khoá PIN vẫn xác thực RSA được", vc.internalAuth(random(32)), 0x9000);

        section("UNBLOCK_PUK");
        String pin3 = "654321";
        expectSw("PUK sai -> 63C4", vc.unblockPuk("00000000", pin3), 0x63C4);
        expectSw("PUK sai định dạng -> 6A80 (không trừ lượt)", vc.unblockPuk("1234", pin3), 0x6A80);
        check("PUK còn 4 lượt", vc.getStatus().pukTriesLeft() == 4, "");
        expectSw("PUK đúng + PIN mới", vc.unblockPuk(PUK, pin3), 0x9000);
        st = vc.getStatus();
        check("Hoạt động, PIN 3 lượt, PUK 5 lượt",
                st.state() == 1 && st.pinTriesLeft() == 3 && st.pukTriesLeft() == 5, st.toString());
        expectSw("PIN mới đăng nhập được", vc.verifyPin(pin3), 0x9000);
        expectSw("UNBLOCK_PUK khi đang Hoạt động cũng được", vc.unblockPuk(PUK, PIN), 0x9000);
        expectSw("PIN sau khi đặt lại", vc.verifyPin(PIN), 0x9000);

        section("Sai PUK 5 lần -> thẻ Vô hiệu (chạy cuối vì không đảo ngược được)");
        for (int i = 4; i >= 1; i--) {
            expectSw("PUK sai -> 63C" + i, vc.unblockPuk("00000000", pin3), 0x63C0 | i);
        }
        expectSw("PUK sai lần 5 -> 6983", vc.unblockPuk("00000000", pin3), 0x6983);
        st = vc.getStatus();
        check("Trạng thái = Vô hiệu (05)", st.state() == VaultCard.STATE_DISABLED, st.toString());
        expectSw("PUK đúng cũng bị từ chối -> 6985", vc.unblockPuk(PUK, pin3), 0x6985);
        expectSw("VERIFY_PIN -> 6985", vc.verifyPin(PIN), 0x6985);
        expectSw("INTERNAL_AUTH -> 6985", vc.internalAuth(random(32)), 0x6985);
        expectSw("GET_PUBKEY vẫn đọc được", vc.getPubKeyPart(2), 0x9000);
    }
}
