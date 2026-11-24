package vault.tester;

/** Thẻ chuẩn dùng chung cho các giai đoạn 2-4. */
public final class Fixture {
    static final String CARD_ID = "SC000001";
    static final String PIN = "123456";
    static final String PUK = "12345678";
    static final byte[] ADMIN_KEY = Check.random(16);

    /** Nạp lại applet (giả lập cắm một thẻ trắng mới). AllTests gán giá trị này. */
    interface Redeploy {
        void run() throws Exception;
    }

    static Redeploy redeploy;

    private Fixture() {}

    /** SELECT + ISSUE + VERIFY_PIN. */
    static void issueAndLogin(VaultCard vc) throws Exception {
        VaultCard.require(vc.select());
        VaultCard.require(vc.issue(CARD_ID, PIN, PUK, ADMIN_KEY));
        VaultCard.require(vc.verifyPin(PIN));
    }
}
