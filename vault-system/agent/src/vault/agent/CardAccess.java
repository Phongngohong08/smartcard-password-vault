package vault.agent;

import java.net.InetSocketAddress;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import javax.smartcardio.Card;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.TerminalFactory;

import vault.tester.Simulator;
import vault.tester.VaultCard;

/**
 * Mở kết nối tới thẻ cho MỖI thao tác rồi đóng lại, có khoá để các thao tác không chen nhau.
 * Nhờ vậy chuỗi ADMIN_CHALLENGE -> ADMIN_AUTH không bao giờ bị lệnh khác chen vào giữa,
 * và simulator được nhả ra giữa các request (console Eclipse vẫn dùng được).
 *
 * reader: "socket:localhost:9025" (simulator) hoặc "pcsc" / "pcsc:<tên đầu đọc>" (thẻ thật).
 */
public class CardAccess {

    public interface CardOp<T> {
        T run(VaultCard vc) throws Exception;
    }

    private final String reader;

    public CardAccess(String reader) {
        this.reader = reader;
    }

    public String reader() {
        return reader;
    }

    public synchronized <T> T with(CardOp<T> op) {
        Card card = connect();
        try {
            VaultCard vc = new VaultCard(cmd -> card.getBasicChannel().transmit(new CommandAPDU(cmd)).getBytes());
            VaultCard.Resp sel = vc.select();
            if (!sel.ok()) {
                throw new AgentException(409, "NO_APPLET",
                        String.format("Thẻ không có applet Vault (SELECT trả %04X)", sel.sw()), sel.sw());
            }
            return op.run(vc);
        } catch (AgentException e) {
            throw e;
        } catch (CardException e) {
            throw new AgentException(503, "CARD_IO", "Mất kết nối với thẻ: " + e.getMessage());
        } catch (Exception e) {
            throw new AgentException(500, "CARD_ERROR", "Lỗi khi làm việc với thẻ: " + e);
        } finally {
            try {
                card.disconnect(false);
            } catch (CardException ignored) {
                // bỏ qua
            }
        }
    }

    /** Dùng cho /dev/blank-card: chạy thao tác trên kênh thô (không SELECT applet). */
    public synchronized void withRaw(java.util.function.Consumer<Card> op) {
        Card card = connect();
        try {
            op.accept(card);
        } finally {
            try {
                card.disconnect(false);
            } catch (CardException ignored) {
                // bỏ qua
            }
        }
    }

    private Card connect() {
        try {
            CardTerminal t = terminal();
            if (!t.waitForCardPresent(1500)) {
                throw new AgentException(404, "NO_CARD", "Chưa cắm thẻ vào đầu đọc " + t.getName());
            }
            // Simulator chỉ phục vụ một kết nối: nếu chương trình khác đang giữ, connect() sẽ chờ mãi.
            // Đặt thời hạn 3 giây; kết nối nào đến muộn thì đóng ngay để không chiếm simulator.
            CompletableFuture<Card> f = CompletableFuture.supplyAsync(() -> {
                try {
                    return t.connect("*");
                } catch (CardException e) {
                    throw new CompletionException(e);
                }
            });
            try {
                return f.get(3, TimeUnit.SECONDS);
            } catch (TimeoutException e) {
                f.thenAccept(late -> {
                    try {
                        late.disconnect(false);
                    } catch (CardException ignored) {
                        // bỏ qua
                    }
                });
                throw new AgentException(503, "READER_BUSY",
                        "Đầu đọc / simulator đang bận - có thể console APDU của Eclipse đang giữ kết nối, hãy Disconnect");
            } catch (ExecutionException e) {
                throw e.getCause() instanceof Exception ex ? ex : e;
            }
        } catch (AgentException e) {
            throw e;
        } catch (Exception e) {
            String hint = reader.startsWith("socket")
                    ? " - simulator chưa chạy, hoặc đang bị chương trình khác (console APDU của Eclipse) giữ kết nối"
                    : "";
            throw new AgentException(503, "NO_READER", "Không kết nối được " + reader + hint + " (" + e.getMessage() + ")");
        }
    }

    private CardTerminal terminal() throws Exception {
        String[] p = reader.split(":", 2);
        if (p[0].equals("socket")) {
            String[] hp = p[1].split(":");
            TerminalFactory tf = TerminalFactory.getInstance("SocketCardTerminalFactoryType",
                    List.of(new InetSocketAddress(hp[0], Integer.parseInt(hp[1]))), "SocketCardTerminalProvider");
            return tf.terminals().list().get(0);
        }
        List<CardTerminal> list = TerminalFactory.getDefault().terminals().list();
        if (list.isEmpty()) {
            throw new AgentException(503, "NO_READER", "Không tìm thấy đầu đọc thẻ PC/SC nào");
        }
        if (p.length > 1 && !p[1].isBlank()) {
            for (CardTerminal t : list) {
                if (t.getName().equals(p[1])) {
                    return t;
                }
            }
            throw new AgentException(503, "NO_READER", "Không có đầu đọc tên " + p[1]);
        }
        for (CardTerminal t : list) {
            if (t.isCardPresent()) {
                return t;
            }
        }
        return list.get(0);
    }

    /** Nạp lại applet trên simulator: giả lập cắm một thẻ trắng mới. */
    public void redeploy(String capPath, String propsPath) {
        withRaw(card -> {
            try {
                Simulator.redeploy(card.getBasicChannel(), capPath, propsPath);
            } catch (Exception e) {
                throw new AgentException(500, "DEPLOY_FAILED", "Nạp applet thất bại: " + e.getMessage());
            }
        });
    }
}
