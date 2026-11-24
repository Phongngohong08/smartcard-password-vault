package vault.tester;

import java.security.SecureRandom;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;

import vault.tester.VaultCard.Resp;

/** Các hàm kiểm tra dùng chung cho mọi giai đoạn. */
public final class Check {
    static int pass, fail;
    static final SecureRandom RNG = new SecureRandom();

    private Check() {}

    static void section(String name) {
        System.out.println("\n--- " + name);
    }

    static void expectSw(String name, Resp r, int sw) {
        check(name, r.sw() == sw, String.format("mong đợi %04X, nhận %s", sw, r));
    }

    /** Lệnh phải thành công và trả về đúng dữ liệu mong đợi. */
    static void expectData(String name, Resp r, byte[] expected) {
        check(name, r.ok() && Arrays.equals(r.data(), expected),
                String.format("mong đợi 9000 %s, nhận %s", Hex.of(expected), r));
    }

    static void check(String name, boolean ok, String detail) {
        if (ok) {
            pass++;
            System.out.println("  [ĐẠT] " + name);
        } else {
            fail++;
            System.out.println("  [LỖI] " + name + "  <-- " + detail);
        }
    }

    static byte[] random(int n) {
        byte[] b = new byte[n];
        RNG.nextBytes(b);
        return b;
    }

    static boolean verifyRsa(RSAPublicKey pub, byte[] msg, byte[] sig) throws Exception {
        Signature s = Signature.getInstance("SHA256withRSA");
        s.initVerify(pub);
        s.update(msg);
        return s.verify(sig);
    }
}
