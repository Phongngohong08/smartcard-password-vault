package vault.agent;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** JSON tối giản (không cần thư viện ngoài): đọc thành Map/List/String/Double/Boolean/null, ghi ngược lại. */
public final class Json {
    private final String s;
    private int i;

    private Json(String s) {
        this.s = s;
    }

    public static Object parse(String text) {
        Json p = new Json(text);
        p.ws();
        Object v = p.value();
        p.ws();
        if (p.i != p.s.length()) {
            throw new IllegalArgumentException("JSON thừa ký tự ở vị trí " + p.i);
        }
        return v;
    }

    @SuppressWarnings("unchecked")
    public static Map<String, Object> parseObject(String text) {
        if (text == null || text.isBlank()) {
            return new LinkedHashMap<>();
        }
        Object v = parse(text);
        if (!(v instanceof Map)) {
            throw new IllegalArgumentException("Cần một đối tượng JSON");
        }
        return (Map<String, Object>) v;
    }

    private Object value() {
        char c = peek();
        switch (c) {
        case '{': return object();
        case '[': return array();
        case '"': return string();
        case 't': expect("true"); return Boolean.TRUE;
        case 'f': expect("false"); return Boolean.FALSE;
        case 'n': expect("null"); return null;
        default: return number();
        }
    }

    private Map<String, Object> object() {
        Map<String, Object> m = new LinkedHashMap<>();
        i++;
        ws();
        if (peek() == '}') {
            i++;
            return m;
        }
        while (true) {
            ws();
            String k = string();
            ws();
            if (s.charAt(i++) != ':') {
                throw new IllegalArgumentException("Thiếu ':' ở vị trí " + i);
            }
            ws();
            m.put(k, value());
            ws();
            char c = s.charAt(i++);
            if (c == '}') {
                return m;
            }
            if (c != ',') {
                throw new IllegalArgumentException("Thiếu ',' ở vị trí " + i);
            }
        }
    }

    private List<Object> array() {
        List<Object> l = new ArrayList<>();
        i++;
        ws();
        if (peek() == ']') {
            i++;
            return l;
        }
        while (true) {
            ws();
            l.add(value());
            ws();
            char c = s.charAt(i++);
            if (c == ']') {
                return l;
            }
            if (c != ',') {
                throw new IllegalArgumentException("Thiếu ',' ở vị trí " + i);
            }
        }
    }

    private String string() {
        if (s.charAt(i++) != '"') {
            throw new IllegalArgumentException("Cần chuỗi ở vị trí " + i);
        }
        StringBuilder b = new StringBuilder();
        while (true) {
            char c = s.charAt(i++);
            if (c == '"') {
                return b.toString();
            }
            if (c == '\\') {
                char e = s.charAt(i++);
                switch (e) {
                case 'n': b.append('\n'); break;
                case 't': b.append('\t'); break;
                case 'r': b.append('\r'); break;
                case 'b': b.append('\b'); break;
                case 'f': b.append('\f'); break;
                case 'u': b.append((char) Integer.parseInt(s.substring(i, i + 4), 16)); i += 4; break;
                default: b.append(e);
                }
            } else {
                b.append(c);
            }
        }
    }

    private Double number() {
        int start = i;
        while (i < s.length() && "+-0123456789.eE".indexOf(s.charAt(i)) >= 0) {
            i++;
        }
        if (start == i) {
            throw new IllegalArgumentException("Giá trị JSON không hợp lệ ở vị trí " + i);
        }
        return Double.parseDouble(s.substring(start, i));
    }

    private void expect(String word) {
        if (!s.startsWith(word, i)) {
            throw new IllegalArgumentException("Cần '" + word + "' ở vị trí " + i);
        }
        i += word.length();
    }

    private char peek() {
        if (i >= s.length()) {
            throw new IllegalArgumentException("JSON kết thúc đột ngột");
        }
        return s.charAt(i);
    }

    private void ws() {
        while (i < s.length() && Character.isWhitespace(s.charAt(i))) {
            i++;
        }
    }

    // ------------------------------------------------------------------ ghi

    public static String write(Object v) {
        StringBuilder b = new StringBuilder();
        write(b, v);
        return b.toString();
    }

    private static void write(StringBuilder b, Object v) {
        if (v == null) {
            b.append("null");
        } else if (v instanceof String str) {
            quote(b, str);
        } else if (v instanceof Number || v instanceof Boolean) {
            if (v instanceof Double d && d == Math.rint(d) && !Double.isInfinite(d)) {
                b.append(d.longValue());
            } else {
                b.append(v);
            }
        } else if (v instanceof Map<?, ?> m) {
            b.append('{');
            boolean first = true;
            for (Map.Entry<?, ?> e : m.entrySet()) {
                if (!first) {
                    b.append(',');
                }
                first = false;
                quote(b, String.valueOf(e.getKey()));
                b.append(':');
                write(b, e.getValue());
            }
            b.append('}');
        } else if (v instanceof List<?> l) {
            b.append('[');
            for (int k = 0; k < l.size(); k++) {
                if (k > 0) {
                    b.append(',');
                }
                write(b, l.get(k));
            }
            b.append(']');
        } else {
            quote(b, v.toString());
        }
    }

    private static void quote(StringBuilder b, String s) {
        b.append('"');
        for (char c : s.toCharArray()) {
            switch (c) {
            case '"': b.append("\\\""); break;
            case '\\': b.append("\\\\"); break;
            case '\n': b.append("\\n"); break;
            case '\r': b.append("\\r"); break;
            case '\t': b.append("\\t"); break;
            default:
                if (c < 0x20) {
                    b.append(String.format("\\u%04x", (int) c));
                } else {
                    b.append(c);
                }
            }
        }
        b.append('"');
    }

    /** Tạo Map theo cặp khoá / giá trị: Json.obj("a", 1, "b", "x"). */
    public static Map<String, Object> obj(Object... kv) {
        Map<String, Object> m = new LinkedHashMap<>();
        for (int k = 0; k < kv.length; k += 2) {
            m.put((String) kv[k], kv[k + 1]);
        }
        return m;
    }
}
