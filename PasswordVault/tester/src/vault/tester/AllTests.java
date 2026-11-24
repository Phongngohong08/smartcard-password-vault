package vault.tester;

import javax.smartcardio.Card;

/**
 * Chạy kiểm thử applet trên simulator. Trước mỗi giai đoạn applet được nạp lại (thẻ trắng).
 *
 * Tham số: -cap=<vault.cap> -props=<client.config.properties>
 *          [-host=localhost:9025] [-stages=1,2,3,4,6]
 */
public class AllTests {

    interface Stage {
        void run(VaultCard vc) throws Exception;
    }

    public static void main(String[] args) throws Exception {
        String cap = arg(args, "cap", null);
        String props = arg(args, "props", null);
        String[] host = arg(args, "host", "localhost:9025").split(":");
        String[] stages = arg(args, "stages", "1,2,3,4,6").trim().split("[,\\s]+");

        Card card = Simulator.connect(host[0], Integer.parseInt(host[1]));
        try {
            VaultCard vc = new VaultCard(Simulator.transport(card.getBasicChannel()));
            Fixture.redeploy = () -> Simulator.redeploy(card.getBasicChannel(), cap, props);
            for (String s : stages) {
                Stage stage = switch (s.trim()) {
                    case "1" -> Stage1Test::run;
                    case "2" -> Stage2Test::run;
                    case "3" -> Stage3Test::run;
                    case "4" -> Stage4Test::run;
                    case "6" -> Stage6Test::run;
                    default -> throw new IllegalArgumentException("Không có giai đoạn " + s);
                };
                System.out.printf("%n========== GIAI ĐOẠN %s ==========%n", s.trim());
                Simulator.redeploy(card.getBasicChannel(), cap, props);
                stage.run(vc);
            }
        } finally {
            card.disconnect(false);
        }

        System.out.printf("%n==== KẾT QUẢ: %d đạt, %d lỗi ====%n", Check.pass, Check.fail);
        System.exit(Check.fail == 0 ? 0 : 1);
    }

    static String arg(String[] args, String name, String def) {
        for (String a : args) {
            if (a.startsWith("-" + name + "=")) {
                return a.substring(name.length() + 2);
            }
        }
        if (def == null) {
            throw new IllegalArgumentException("Thiếu tham số -" + name + "=");
        }
        return def;
    }
}
