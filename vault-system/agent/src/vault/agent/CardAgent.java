package vault.agent;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Executors;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import vault.tester.VaultCard;
import vault.tester.VaultCard.Resp;
import vault.tester.VaultCard.Status;

/**
 * Card Agent: chạy trên máy admin, là cầu nối giữa web quản trị (trình duyệt) và thẻ.
 *
 * Chỉ nghe 127.0.0.1. Chỉ nhận request từ các origin cho phép (web quản trị), để một trang web lạ
 * không điều khiển được thẻ. Mọi bí mật (adminKey, phản hồi ADMIN_AUTH) lấy từ Vault server bằng token admin.
 *
 * Tham số: --port=8765 --server=http://127.0.0.1:8080 --reader=socket:localhost:9025
 *          --origins=http://localhost:5173,http://127.0.0.1:8080
 *          --dev --cap=<vault.cap> --props=<client.config.properties>   (bật /dev/blank-card)
 */
public class CardAgent {

    static final String VERSION = "1.0";
    static final HexFormat HEX = HexFormat.of();
    static final String[] STATE_NAMES = { "UNISSUED", "ACTIVE", "PIN_BLOCKED", "ADMIN_LOCKED", "REVOKED", "DISABLED" };

    final CardAccess cards;
    final ServerClient server;
    final Set<String> origins;
    final boolean dev;
    final String cap, props;

    CardAgent(CardAccess cards, ServerClient server, Set<String> origins, boolean dev, String cap, String props) {
        this.cards = cards;
        this.server = server;
        this.origins = origins;
        this.dev = dev;
        this.cap = cap;
        this.props = props;
    }

    public static void main(String[] args) throws IOException {
        int port = Integer.parseInt(arg(args, "port", "8765"));
        String serverUrl = arg(args, "server", "http://127.0.0.1:8080");
        String reader = arg(args, "reader", "socket:localhost:9025");
        Set<String> origins = Set.of(arg(args, "origins",
                "http://localhost:5173,http://127.0.0.1:5173,http://localhost:8080,http://127.0.0.1:8080").split(","));
        boolean dev = List.of(args).contains("--dev");

        CardAgent agent = new CardAgent(new CardAccess(reader), new ServerClient(serverUrl), origins, dev,
                arg(args, "cap", ""), arg(args, "props", ""));
        HttpServer http = HttpServer.create(new InetSocketAddress("127.0.0.1", port), 0);
        http.createContext("/", agent::handle);
        http.setExecutor(Executors.newFixedThreadPool(4));
        http.start();
        System.out.printf("Card Agent %s: http://127.0.0.1:%d  (thẻ: %s, server: %s%s)%n",
                VERSION, port, reader, serverUrl, dev ? ", CHẾ ĐỘ DEV" : "");
    }

    // ------------------------------------------------------------------ HTTP

    void handle(HttpExchange ex) throws IOException {
        String origin = ex.getRequestHeaders().getFirst("Origin");
        try {
            if (origin != null && !origins.contains(origin)) {
                throw new AgentException(403, "BAD_ORIGIN", "Origin " + origin + " không được phép dùng agent");
            }
            if (origin != null) {
                ex.getResponseHeaders().set("Access-Control-Allow-Origin", origin);
                ex.getResponseHeaders().set("Vary", "Origin");
            }
            if (ex.getRequestMethod().equals("OPTIONS")) {
                ex.getResponseHeaders().set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
                ex.getResponseHeaders().set("Access-Control-Allow-Headers", "Content-Type, Authorization");
                ex.getResponseHeaders().set("Access-Control-Allow-Private-Network", "true");
                ex.getResponseHeaders().set("Access-Control-Max-Age", "600");
                ex.sendResponseHeaders(204, -1);
                return;
            }
            String route = ex.getRequestMethod() + " " + ex.getRequestURI().getPath();
            Map<String, Object> body = ex.getRequestMethod().equals("POST") ? Json.parseObject(readBody(ex)) : Map.of();
            String token = bearer(ex);
            // Thao tác cần quyền admin: kiểm tra token TRƯỚC khi động vào thẻ
            if ((route.equals("POST /card/issue") || route.equals("POST /card/admin")) && token == null) {
                throw new AgentException(401, "NO_TOKEN", "Thiếu token admin - hãy đăng nhập web quản trị");
            }
            Object result = switch (route) {
                case "GET /health" -> Json.obj("ok", true, "version", VERSION, "reader", cards.reader(), "dev", dev);
                case "GET /card" -> cardStatus();
                case "POST /card/issue" -> issue(body, token);
                case "POST /card/sign" -> sign(body);
                case "POST /card/admin" -> adminAction(body, token);
                case "POST /dev/blank-card" -> blankCard();
                default -> throw new AgentException(404, "NOT_FOUND", "Không có " + route);
            };
            send(ex, 200, result);
        } catch (AgentException e) {
            send(ex, e.status, Json.obj("error", e.getMessage(), "code", e.code,
                    "sw", e.sw == null ? null : String.format("%04X", e.sw)));
        } catch (IllegalArgumentException e) {
            send(ex, 400, Json.obj("error", "Dữ liệu không hợp lệ: " + e.getMessage(), "code", "BAD_REQUEST"));
        } catch (RuntimeException e) {
            e.printStackTrace();
            send(ex, 500, Json.obj("error", "Lỗi agent: " + e, "code", "INTERNAL"));
        }
    }

    // ------------------------------------------------------------------ thao tác

    /** GET /card: trạng thái thẻ đang cắm. Không có thẻ / không có đầu đọc thì present = false. */
    Map<String, Object> cardStatus() {
        try {
            return cards.with(vc -> statusJson(vc.getStatus()));
        } catch (AgentException e) {
            return Json.obj("present", false, "error", e.getMessage(), "code", e.code);
        }
    }

    static Map<String, Object> statusJson(Status s) {
        return Json.obj("present", true, "state", s.state(), "stateName", stateName(s.state()),
                "cardId", s.state() == VaultCard.STATE_UNISSUED ? null : s.cardId(),
                "pinTriesLeft", s.pinTriesLeft(), "pukTriesLeft", s.pukTriesLeft());
    }

    /**
     * POST /card/issue {cardId, pin, puk, profile:{name, dob, email, phone}, avatarBase64}
     * Phát hành thẻ trắng: lấy adminKey từ server -> ISSUE -> VERIFY_PIN -> SET_PROFILE -> SET_AVATAR -> GET_PUBKEY.
     * Bước đăng ký khoá công khai và kiểm tra RSA do web gọi server sau đó.
     */
    Map<String, Object> issue(Map<String, Object> body, String token) {
        String cardId = str(body, "cardId").toUpperCase();
        String pin = str(body, "pin");
        String puk = str(body, "puk");
        Map<String, Object> profile = map(body, "profile");
        byte[] profileTlv = profileTlv(profile);
        byte[] avatar = body.get("avatarBase64") instanceof String s && !s.isBlank() ? Base64.getDecoder().decode(s) : null;
        if (avatar != null && avatar.length > 16 * VaultCard.AVATAR_CHUNK) {
            throw new AgentException(400, "AVATAR_TOO_BIG", "Ảnh tối đa 3 072 byte (hiện " + avatar.length + ")");
        }

        return cards.with(vc -> {
            Status st = vc.getStatus();
            if (st.state() != VaultCard.STATE_UNISSUED) {
                throw new AgentException(409, "NOT_BLANK",
                        "Thẻ đang cắm không phải thẻ trắng (trạng thái " + stateName(st.state()) + ", mã " + st.cardId() + ")");
            }
            List<String> steps = new ArrayList<>();
            byte[] adminKey = HEX.parseHex((String) server.post("/api/cards/" + cardId + "/issue-key", token, Map.of())
                    .get("adminKey"));
            steps.add("Lấy adminKey của thẻ từ server");

            long t0 = System.currentTimeMillis();
            check(vc.issue(cardId, pin, puk, adminKey), "ISSUE");
            steps.add("ISSUE: thẻ sinh salt, Master Key và cặp khoá RSA-2048 (" + (System.currentTimeMillis() - t0) + " ms)");
            check(vc.verifyPin(pin), "VERIFY_PIN");
            steps.add("VERIFY_PIN bằng PIN ban đầu");
            if (profileTlv.length > 0) {
                check(vc.setProfile(profileTlv), "SET_PROFILE");
                steps.add("SET_PROFILE (" + profileTlv.length + " byte, mã hoá trên thẻ)");
            }
            if (avatar != null) {
                vc.writeAvatar(avatar);
                steps.add("SET_AVATAR (" + avatar.length + " byte)");
            }
            RSAPublicKey pub = vc.getPublicKey();
            steps.add("GET_PUBKEY x3");
            vc.logout();
            byte[] mod = toFixed(pub.getModulus().toByteArray(), 256);
            return Json.obj("cardId", cardId, "modulusHex", HEX.formatHex(mod),
                    "exponentHex", HEX.formatHex(pub.getPublicExponent().toByteArray()), "steps", steps);
        });
    }

    /** POST /card/sign {challenge}: INTERNAL_AUTH + GET_SIGNATURE x2. */
    Map<String, Object> sign(Map<String, Object> body) {
        byte[] ch = HEX.parseHex(str(body, "challenge"));
        return cards.with(vc -> {
            Status st = vc.getStatus();
            check(vc.internalAuth(ch), "INTERNAL_AUTH");
            byte[] sig = VaultCard.join(check(vc.getSignaturePart(0), "GET_SIGNATURE").data(),
                    check(vc.getSignaturePart(1), "GET_SIGNATURE").data());
            return Json.obj("cardId", st.cardId(), "signature", HEX.formatHex(sig));
        });
    }

    /**
     * POST /card/admin {cardId, action: LOCK | UNLOCK | REVOKE}
     * ADMIN_CHALLENGE -> server tính phản hồi -> ADMIN_AUTH -> thao tác, trong cùng một kết nối.
     */
    Map<String, Object> adminAction(Map<String, Object> body, String token) {
        String cardId = str(body, "cardId").toUpperCase();
        String action = str(body, "action");
        if (!Set.of("LOCK", "UNLOCK", "REVOKE").contains(action)) {
            throw new AgentException(400, "BAD_ACTION", "action phải là LOCK, UNLOCK hoặc REVOKE");
        }
        return cards.with(vc -> {
            Status st = vc.getStatus();
            if (!cardId.equals(st.cardId())) {
                throw new AgentException(409, "WRONG_CARD", "Thẻ đang cắm là " + st.cardId() + ", không phải " + cardId);
            }
            byte[] ch = check(vc.adminChallenge(), "ADMIN_CHALLENGE").data();
            String resp = (String) server.post("/api/cards/" + cardId + "/admin-response", token,
                    Json.obj("challenge", HEX.formatHex(ch))).get("response");
            check(vc.adminAuth(HEX.parseHex(resp)), "ADMIN_AUTH");
            switch (action) {
            case "LOCK" -> check(vc.adminLock(true), "ADMIN_LOCK");
            case "UNLOCK" -> check(vc.adminLock(false), "ADMIN_LOCK");
            default -> check(vc.revoke(), "REVOKE");
            }
            return statusJson(vc.getStatus());
        });
    }

    /** POST /dev/blank-card: nạp lại applet trên simulator = cắm một thẻ trắng mới (chỉ chế độ dev). */
    Map<String, Object> blankCard() {
        if (!dev || cap.isBlank()) {
            throw new AgentException(403, "NOT_DEV", "Chỉ dùng được khi agent chạy với --dev --cap=... --props=...");
        }
        cards.redeploy(cap, props);
        return cardStatus();
    }

    // ------------------------------------------------------------------ tiện ích

    /** Ném lỗi kèm thông báo dễ hiểu nếu lệnh APDU không trả 9000. */
    static Resp check(Resp r, String cmd) {
        if (r.ok()) {
            return r;
        }
        String why = switch (r.sw()) {
            case 0x6982 -> "chưa xác thực";
            case 0x6983 -> "PIN/PUK bị khoá";
            case 0x6985 -> "sai trạng thái thẻ hoặc sai thứ tự lệnh";
            case 0x6A80 -> "dữ liệu sai định dạng (PIN 6-12 ký tự, PUK 8 chữ số, mã thẻ 8 ký tự A-Z 0-9...)";
            case 0x6700 -> "sai độ dài dữ liệu";
            case 0x6D00 -> "applet không hỗ trợ lệnh";
            default -> (r.sw() & 0xFFF0) == 0x63C0 ? "sai mã, còn " + (r.sw() & 0x0F) + " lần" : "lỗi";
        };
        throw new AgentException(422, "CARD_SW", cmd + " thất bại: " + why + String.format(" (SW %04X)", r.sw()), r.sw());
    }

    static byte[] profileTlv(Map<String, Object> p) {
        byte[][] parts = new byte[4][];
        String[] keys = { "name", "dob", "email", "phone" };
        int n = 0;
        for (int k = 0; k < 4; k++) {
            Object v = p.get(keys[k]);
            if (v instanceof String s && !s.isBlank()) {
                parts[n++] = VaultCard.tlv(k + 1, s.trim());
            }
        }
        return VaultCard.join(java.util.Arrays.copyOf(parts, n));
    }

    static byte[] toFixed(byte[] b, int len) {
        byte[] r = new byte[len];
        int copy = Math.min(b.length, len);
        System.arraycopy(b, b.length - copy, r, len - copy, copy);
        return r;
    }

    static String stateName(int s) {
        return s >= 0 && s < STATE_NAMES.length ? STATE_NAMES[s] : "UNKNOWN";
    }

    static String str(Map<String, Object> m, String k) {
        Object v = m.get(k);
        if (!(v instanceof String s) || s.isBlank()) {
            throw new AgentException(400, "MISSING_FIELD", "Thiếu trường " + k);
        }
        return s;
    }

    @SuppressWarnings("unchecked")
    static Map<String, Object> map(Map<String, Object> m, String k) {
        return m.get(k) instanceof Map ? (Map<String, Object>) m.get(k) : Map.of();
    }

    static String bearer(HttpExchange ex) {
        String h = ex.getRequestHeaders().getFirst("Authorization");
        return h != null && h.startsWith("Bearer ") ? h.substring(7) : null;
    }

    static String readBody(HttpExchange ex) throws IOException {
        try (InputStream in = ex.getRequestBody()) {
            return new String(in.readNBytes(256 * 1024), StandardCharsets.UTF_8);
        }
    }

    static void send(HttpExchange ex, int status, Object body) throws IOException {
        byte[] b = Json.write(body).getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
        ex.sendResponseHeaders(status, b.length);
        try (OutputStream out = ex.getResponseBody()) {
            out.write(b);
        }
    }

    static String arg(String[] args, String name, String def) {
        for (String a : args) {
            if (a.startsWith("--" + name + "=")) {
                return a.substring(name.length() + 3);
            }
        }
        return def;
    }
}
