package vault.agent;

/** Lỗi trả về cho web: mã HTTP + thông báo tiếng Việt (+ SW của thẻ nếu có). */
public class AgentException extends RuntimeException {
    final int status;
    final String code;
    final Integer sw;

    public AgentException(int status, String code, String message) {
        this(status, code, message, null);
    }

    public AgentException(int status, String code, String message, Integer sw) {
        super(message);
        this.status = status;
        this.code = code;
        this.sw = sw;
    }
}
