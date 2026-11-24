package vault.tester;

import java.io.FileInputStream;
import java.net.InetSocketAddress;
import java.util.List;
import java.util.Properties;

import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.TerminalFactory;

import com.oracle.javacard.ams.AMService;
import com.oracle.javacard.ams.AMServiceFactory;
import com.oracle.javacard.ams.config.CAPFile;
import com.oracle.javacard.ams.script.ScriptFailedException;

/** Kết nối simulator qua socket và nạp lại applet (xoá bản cũ nếu có). */
public final class Simulator {

    private static final String ISD = "aid:A000000151000000";
    private static final String PKG = "aid:112233445500";
    private static final String APPLET = "aid:11223344550001";

    private Simulator() {}

    public static Card connect(String host, int port) throws Exception {
        TerminalFactory tf = TerminalFactory.getInstance("SocketCardTerminalFactoryType",
                List.of(new InetSocketAddress(host, port)), "SocketCardTerminalProvider");
        CardTerminal t = tf.terminals().list().get(0);
        if (!t.waitForCardPresent(10000)) {
            throw new IllegalStateException("Không kết nối được simulator " + host + ":" + port
                    + " - hãy kiểm tra jcsw.exe đang chạy");
        }
        return t.connect("*");
    }

    /** Xoá applet cũ (nếu có) rồi nạp và cài đặt file CAP mới: thẻ trở về trạng thái trắng. */
    public static void redeploy(CardChannel ch, String capPath, String propsPath) throws Exception {
        Properties props = new Properties();
        try (FileInputStream in = new FileInputStream(propsPath)) {
            props.load(in);
        }
        AMService ams = AMServiceFactory.getInstance("GP2.2");
        ams.setProperties(props);

        try {
            ams.openSession(ISD).uninstall(APPLET).close().run(ch);
        } catch (ScriptFailedException e) {
            // chưa cài instance - bỏ qua
        }
        try {
            ams.openSession(ISD).unload(PKG, true).close().run(ch);
        } catch (ScriptFailedException e) {
            // chưa nạp package - bỏ qua
        }
        ams.openSession(ISD)
                .load(PKG, CAPFile.from(capPath).getBytes())
                .install(PKG, APPLET, APPLET)
                .close()
                .run(ch);
    }

    public static VaultCard.Transport transport(CardChannel ch) {
        return cmd -> ch.transmit(new CommandAPDU(cmd)).getBytes();
    }
}
