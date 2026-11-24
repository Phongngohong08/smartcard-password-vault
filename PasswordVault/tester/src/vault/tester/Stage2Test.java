package vault.tester;

import static vault.tester.Check.*;
import static vault.tester.VaultCard.join;
import static vault.tester.VaultCard.tlv;

import java.util.Arrays;

/** Giai đoạn 2: hồ sơ chủ thẻ và ảnh đại diện. */
public class Stage2Test {

    static void run(VaultCard vc) throws Exception {
        byte[] profile = join(
                tlv(0x01, "Nguyễn Văn An"),
                tlv(0x02, "2004-05-17"),
                tlv(0x03, "an.nguyen@example.com"),
                tlv(0x04, "0901234567"));

        section("Chưa đăng nhập PIN");
        VaultCard.require(vc.select());
        VaultCard.require(vc.issue(Fixture.CARD_ID, Fixture.PIN, Fixture.PUK, Fixture.ADMIN_KEY));
        expectSw("SET_PROFILE -> 6982", vc.setProfile(profile), 0x6982);
        expectSw("GET_PROFILE -> 6982", vc.getProfile(), 0x6982);
        expectSw("GET_AVATAR -> 6982", vc.getAvatarChunk(0xFF), 0x6982);
        VaultCard.require(vc.verifyPin(Fixture.PIN));

        section("SET_PROFILE - dữ liệu sai");
        expectSw("Chưa có hồ sơ -> GET_PROFILE 6A88", vc.getProfile(), 0x6A88);
        expectSw("Không có dữ liệu -> 6700", vc.setProfile(new byte[0]), 0x6700);
        expectSw("Tag lạ 05 -> 6A80", vc.setProfile(tlv(0x05, "x")), 0x6A80);
        expectSw("Họ tên 65 byte -> 6A80", vc.setProfile(tlv(0x01, "A".repeat(65))), 0x6A80);
        expectSw("Ngày sinh 9 ký tự -> 6A80", vc.setProfile(tlv(0x02, "2004-5-17")), 0x6A80);
        expectSw("SĐT 17 số -> 6A80", vc.setProfile(tlv(0x04, "1".repeat(17))), 0x6A80);
        expectSw("Họ tên rỗng -> 6A80", vc.setProfile(tlv(0x01, "")), 0x6A80);
        expectSw("Tag lặp -> 6A80", vc.setProfile(join(tlv(0x01, "A"), tlv(0x01, "B"))), 0x6A80);
        expectSw("TLV cụt (độ dài vượt dữ liệu) -> 6A80", vc.setProfile(new byte[] { 0x01, 0x05, 'A', 'B' }), 0x6A80);
        expectSw("Vẫn chưa có hồ sơ", vc.getProfile(), 0x6A88);

        section("SET_PROFILE / GET_PROFILE");
        expectSw("Ghi hồ sơ (tiếng Việt UTF-8)", vc.setProfile(profile), 0x9000);
        expectData("Đọc lại đúng từng byte", vc.getProfile(), profile);
        byte[] maxProfile = join(tlv(0x01, "N".repeat(64)), tlv(0x02, "2000-01-01"),
                tlv(0x03, "e".repeat(64)), tlv(0x04, "9".repeat(16)));
        expectSw("Hồ sơ tối đa (" + maxProfile.length + " byte)", vc.setProfile(maxProfile), 0x9000);
        expectData("Đọc lại hồ sơ tối đa", vc.getProfile(), maxProfile);
        byte[] partial = tlv(0x01, "Chỉ có tên");
        expectSw("Hồ sơ chỉ có họ tên", vc.setProfile(partial), 0x9000);
        expectData("Ghi đè hồ sơ cũ", vc.getProfile(), partial);
        VaultCard.require(vc.setProfile(profile));

        section("Master Key không đổi sau khi đổi PIN / mở bằng PUK");
        expectSw("CHANGE_PIN", vc.changePin(Fixture.PIN, "newpin99"), 0x9000);
        expectSw("LOGOUT", vc.logout(), 0x9000);
        expectSw("Sau LOGOUT -> GET_PROFILE 6982", vc.getProfile(), 0x6982);
        VaultCard.require(vc.verifyPin("newpin99"));
        expectData("Đăng nhập PIN mới, đọc được hồ sơ cũ", vc.getProfile(), profile);
        for (int i = 0; i < 3; i++) {
            vc.verifyPin("000000");
        }
        check("Đã khoá PIN", vc.getStatus().state() == VaultCard.STATE_PIN_BLOCKED, "");
        expectSw("Thẻ khoá PIN -> GET_PROFILE 6985", vc.getProfile(), 0x6985);
        VaultCard.require(vc.unblockPuk(Fixture.PUK, Fixture.PIN));
        VaultCard.require(vc.verifyPin(Fixture.PIN));
        expectData("Mở bằng PUK, đọc được hồ sơ cũ", vc.getProfile(), profile);
        VaultCard.require(vc.select());
        expectSw("SELECT lại (deselect) -> phiên mất, 6982", vc.getProfile(), 0x6982);
        VaultCard.require(vc.verifyPin(Fixture.PIN));

        section("Ảnh đại diện - lỗi");
        expectData("Chưa có ảnh -> số khối = 0", vc.getAvatarChunk(0xFF), new byte[] { 0 });
        expectSw("Đọc khối 0 khi chưa có ảnh -> 6A88", vc.getAvatarChunk(0), 0x6A88);
        expectSw("Khối 16 -> 6A86", vc.getAvatarChunk(16), 0x6A86);
        expectSw("P2 = 17 khối -> 6A86", vc.setAvatarChunk(0, 17, new byte[10]), 0x6A86);
        expectSw("P2 = 0 -> 6A86", vc.setAvatarChunk(0, 0, new byte[10]), 0x6A86);
        expectSw("P1 >= P2 -> 6A86", vc.setAvatarChunk(3, 3, new byte[10]), 0x6A86);
        expectSw("Khối 193 byte -> 6700", vc.setAvatarChunk(0, 1, new byte[193]), 0x6700);
        expectSw("Khối rỗng -> 6700", vc.setAvatarChunk(0, 1, new byte[0]), 0x6700);
        expectSw("Ghi khối 1 khi chưa ghi khối 0 -> 6985", vc.setAvatarChunk(1, 2, new byte[10]), 0x6985);

        section("Ảnh đại diện - ghi và đọc");
        byte[] image = random(16 * 192); // ảnh tối đa 3 072 byte
        long t0 = System.currentTimeMillis();
        vc.writeAvatar(image);
        System.out.printf("   (ghi 16 khối mất %d ms)%n", System.currentTimeMillis() - t0);
        expectData("Số khối = 16", vc.getAvatarChunk(0xFF), new byte[] { 16 });
        check("Đọc lại ảnh 3 072 byte đúng từng byte", Arrays.equals(vc.readAvatar(), image), "");
        expectSw("Khối 15 đọc được", vc.getAvatarChunk(15), 0x9000);

        byte[] small = random(300); // 2 khối: 192 + 108
        vc.writeAvatar(small);
        expectData("Ảnh mới 300 byte -> số khối = 2", vc.getAvatarChunk(0xFF), new byte[] { 2 });
        check("Đọc lại ảnh mới đúng", Arrays.equals(vc.readAvatar(), small), "");
        expectSw("Khối 2 của ảnh mới -> 6A88", vc.getAvatarChunk(2), 0x6A88);

        expectSw("Bắt đầu ảnh 3 khối, ghi khối 0", vc.setAvatarChunk(0, 3, random(192)), 0x9000);
        expectSw("Nhảy cóc sang khối 2 -> 6985", vc.setAvatarChunk(2, 3, random(10)), 0x6985);
        expectSw("Đổi tổng số khối giữa chừng -> 6985", vc.setAvatarChunk(1, 4, random(10)), 0x6985);
        expectData("Ảnh ghi dở -> số khối = 0", vc.getAvatarChunk(0xFF), new byte[] { 0 });
        expectSw("Ảnh ghi dở -> đọc khối 0 bị từ chối (6A88)", vc.getAvatarChunk(0), 0x6A88);
        expectSw("Ghi tiếp khối 1", vc.setAvatarChunk(1, 3, random(192)), 0x9000);
        expectSw("Ghi tiếp khối 2", vc.setAvatarChunk(2, 3, random(50)), 0x9000);
        expectData("Ghi đủ -> số khối = 3", vc.getAvatarChunk(0xFF), new byte[] { 3 });

        section("Dữ liệu sau khi đổi PIN vẫn đọc được");
        vc.writeAvatar(image);
        VaultCard.require(vc.changePin(Fixture.PIN, "abcdef"));
        VaultCard.require(vc.logout());
        VaultCard.require(vc.verifyPin("abcdef"));
        check("Ảnh vẫn đúng", Arrays.equals(vc.readAvatar(), image), "");
        expectData("Hồ sơ vẫn đúng", vc.getProfile(), profile);
    }
}
