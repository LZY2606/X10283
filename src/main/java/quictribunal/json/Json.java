package quictribunal.json;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * Minimal dependency-free JSON parser/writer.
 *
 * <p>The parser preserves the exact character offset of every error so import diagnostics can
 * point at a concrete position inside a datagram or a project bundle. {@link #canonical(Object)}
 * emits sorted-key, whitespace-free JSON used for input digests.
 */
public final class Json {

    public static final class JsonException extends RuntimeException {
        public final int position;
        public final int line;
        public final int column;

        public JsonException(String message, int position, int line, int column) {
            super(message + " at line " + line + " column " + column + " (offset " + position + ")");
            this.position = position;
            this.line = line;
            this.column = column;
        }
    }

    private final String src;
    private int pos;

    private Json(String src) {
        this.src = src;
    }

    public static Object parse(String src) {
        Json p = new Json(src);
        p.skipWs();
        Object v = p.readValue();
        p.skipWs();
        if (p.pos < p.src.length()) {
            throw p.err("trailing characters after JSON value");
        }
        return v;
    }

    public static String write(Object value) {
        StringBuilder sb = new StringBuilder();
        writeInto(sb, value, 0);
        return sb.toString();
    }

    public static String canonical(Object value) {
        StringBuilder sb = new StringBuilder();
        canonicalInto(sb, value);
        return sb.toString();
    }

    @SuppressWarnings("unchecked")
    private static void writeInto(StringBuilder sb, Object v, int indent) {
        if (v == null) {
            sb.append("null");
        } else if (v instanceof Boolean || v instanceof Number) {
            sb.append(v.toString());
        } else if (v instanceof String s) {
            quote(sb, s);
        } else if (v instanceof Map<?, ?> m) {
            if (m.isEmpty()) {
                sb.append("{}");
                return;
            }
            sb.append("{\n");
            boolean first = true;
            for (Map.Entry<?, ?> e : m.entrySet()) {
                if (!first) sb.append(",\n");
                first = false;
                indent(sb, indent + 1);
                quote(sb, String.valueOf(e.getKey()));
                sb.append(": ");
                writeInto(sb, e.getValue(), indent + 1);
            }
            sb.append("\n");
            indent(sb, indent);
            sb.append("}");
        } else if (v instanceof List<?> list) {
            if (list.isEmpty()) {
                sb.append("[]");
                return;
            }
            sb.append("[\n");
            for (int i = 0; i < list.size(); i++) {
                if (i > 0) sb.append(",\n");
                indent(sb, indent + 1);
                writeInto(sb, list.get(i), indent + 1);
            }
            sb.append("\n");
            indent(sb, indent);
            sb.append("]");
        } else {
            throw new IllegalArgumentException("cannot serialize " + v.getClass());
        }
    }

    @SuppressWarnings("unchecked")
    private static void canonicalInto(StringBuilder sb, Object v) {
        if (v == null) {
            sb.append("null");
        } else if (v instanceof Boolean || v instanceof Number) {
            sb.append(v.toString());
        } else if (v instanceof String s) {
            quote(sb, s);
        } else if (v instanceof Map<?, ?> raw) {
            Map<String, Object> sorted = new TreeMap<>();
            for (Map.Entry<?, ?> e : raw.entrySet()) {
                sorted.put(String.valueOf(e.getKey()), (Object) e.getValue());
            }
            sb.append("{");
            boolean first = true;
            for (Map.Entry<String, Object> e : sorted.entrySet()) {
                if (!first) sb.append(",");
                first = false;
                quote(sb, e.getKey());
                sb.append(":");
                canonicalInto(sb, e.getValue());
            }
            sb.append("}");
        } else if (v instanceof List<?> list) {
            sb.append("[");
            for (int i = 0; i < list.size(); i++) {
                if (i > 0) sb.append(",");
                canonicalInto(sb, list.get(i));
            }
            sb.append("]");
        } else {
            throw new IllegalArgumentException("cannot canonicalize " + v.getClass());
        }
    }

    private static void indent(StringBuilder sb, int level) {
        sb.append("  ".repeat(level));
    }

    private static void quote(StringBuilder sb, String s) {
        sb.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                case '\b' -> sb.append("\\b");
                case '\f' -> sb.append("\\f");
                default -> {
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
                }
            }
        }
        sb.append('"');
    }

    private Object readValue() {
        skipWs();
        if (pos >= src.length()) throw err("unexpected end of input");
        char c = src.charAt(pos);
        return switch (c) {
            case '{' -> readObject();
            case '[' -> readArray();
            case '"' -> readString();
            case 't', 'f' -> readBoolean();
            case 'n' -> readNull();
            default -> readNumber();
        };
    }

    private Map<String, Object> readObject() {
        expect('{');
        Map<String, Object> m = new LinkedHashMap<>();
        skipWs();
        if (peek() == '}') {
            pos++;
            return m;
        }
        while (true) {
            skipWs();
            String key = readString();
            skipWs();
            expect(':');
            Object value = readValue();
            if (m.containsKey(key)) {
                throw err("duplicate object key '" + key + "'");
            }
            m.put(key, value);
            skipWs();
            char c = next();
            if (c == ',') continue;
            if (c == '}') return m;
            throw err("expected ',' or '}' but found '" + c + "'");
        }
    }

    private List<Object> readArray() {
        expect('[');
        List<Object> list = new ArrayList<>();
        skipWs();
        if (peek() == ']') {
            pos++;
            return list;
        }
        while (true) {
            list.add(readValue());
            skipWs();
            char c = next();
            if (c == ',') continue;
            if (c == ']') return list;
            throw err("expected ',' or ']' but found '" + c + "'");
        }
    }

    private String readString() {
        expect('"');
        StringBuilder sb = new StringBuilder();
        while (true) {
            if (pos >= src.length()) throw err("unterminated string");
            char c = src.charAt(pos++);
            if (c == '"') return sb.toString();
            if (c == '\\') {
                if (pos >= src.length()) throw err("unterminated escape");
                char e = src.charAt(pos++);
                switch (e) {
                    case '"' -> sb.append('"');
                    case '\\' -> sb.append('\\');
                    case '/' -> sb.append('/');
                    case 'n' -> sb.append('\n');
                    case 't' -> sb.append('\t');
                    case 'r' -> sb.append('\r');
                    case 'b' -> sb.append('\b');
                    case 'f' -> sb.append('\f');
                    case 'u' -> {
                        if (pos + 4 > src.length()) throw err("bad unicode escape");
                        String hex = src.substring(pos, pos + 4);
                        try {
                            sb.append((char) Integer.parseInt(hex, 16));
                        } catch (NumberFormatException nfe) {
                            throw err("bad unicode escape \\u" + hex);
                        }
                        pos += 4;
                    }
                    default -> throw err("invalid escape '\\" + e + "'");
                }
            } else if (c < 0x20) {
                throw err("unescaped control character in string");
            } else {
                sb.append(c);
            }
        }
    }

    private Boolean readBoolean() {
        if (src.startsWith("true", pos)) {
            pos += 4;
            return Boolean.TRUE;
        }
        if (src.startsWith("false", pos)) {
            pos += 5;
            return Boolean.FALSE;
        }
        throw err("invalid literal");
    }

    private Object readNull() {
        if (src.startsWith("null", pos)) {
            pos += 4;
            return null;
        }
        throw err("invalid literal");
    }

    private Number readNumber() {
        int start = pos;
        if (peek() == '-') pos++;
        readDigits();
        boolean isDouble = false;
        if (pos < src.length() && src.charAt(pos) == '.') {
            isDouble = true;
            pos++;
            readDigits();
        }
        if (pos < src.length() && (src.charAt(pos) == 'e' || src.charAt(pos) == 'E')) {
            isDouble = true;
            pos++;
            if (pos < src.length() && (src.charAt(pos) == '+' || src.charAt(pos) == '-')) pos++;
            readDigits();
        }
        String token = src.substring(start, pos);
        try {
            if (isDouble) return Double.parseDouble(token);
            return Long.parseLong(token);
        } catch (NumberFormatException nfe) {
            throw err("invalid number '" + token + "'", start);
        }
    }

    private void readDigits() {
        int start = pos;
        while (pos < src.length() && Character.isDigit(src.charAt(pos))) pos++;
        if (pos == start) throw err("expected digits");
    }

    private void skipWs() {
        while (pos < src.length() && Character.isWhitespace(src.charAt(pos))) pos++;
    }

    private char peek() {
        if (pos >= src.length()) throw err("unexpected end of input");
        return src.charAt(pos);
    }

    private char next() {
        if (pos >= src.length()) throw err("unexpected end of input");
        return src.charAt(pos++);
    }

    private void expect(char c) {
        if (pos >= src.length() || src.charAt(pos) != c) {
            throw err("expected '" + c + "'");
        }
        pos++;
    }

    private JsonException err(String message) {
        return err(message, pos);
    }

    private JsonException err(String message, int at) {
        int line = 1;
        int col = 1;
        for (int i = 0; i < at && i < src.length(); i++) {
            if (src.charAt(i) == '\n') {
                line++;
                col = 1;
            } else {
                col++;
            }
        }
        return new JsonException(message, at, line, col);
    }
}
