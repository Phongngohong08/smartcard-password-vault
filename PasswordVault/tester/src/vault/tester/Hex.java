package vault.tester;

public final class Hex {
    private Hex() {}

    public static String of(byte[] b) {
        if (b == null) {
            return "";
        }
        StringBuilder sb = new StringBuilder();
        for (byte x : b) {
            sb.append(String.format("%02X", x));
        }
        return sb.toString();
    }
}
