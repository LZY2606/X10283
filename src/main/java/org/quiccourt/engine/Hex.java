package org.quiccourt.engine;

/** 十六进制工具：只做保真解码，非法输入抛 FormatException 而不是静默截断。 */
public final class Hex {
    private Hex() {}

    public static byte[] decode(String hex) {
        if (hex == null) {
            throw new FormatException("hex is null");
        }
        String h = hex.trim().replace(" ", "");
        if (h.length() % 2 != 0) {
            throw new FormatException("odd-length hex: " + quote(h));
        }
        byte[] out = new byte[h.length() / 2];
        for (int i = 0; i < out.length; i++) {
            int hi = digit(h.charAt(i * 2));
            int lo = digit(h.charAt(i * 2 + 1));
            if (hi < 0 || lo < 0) {
                throw new FormatException("non-hex character in: " + quote(h));
            }
            out[i] = (byte) ((hi << 4) | lo);
        }
        return out;
    }

    public static String encode(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(Character.forDigit((b >> 4) & 0xF, 16));
            sb.append(Character.forDigit(b & 0xF, 16));
        }
        return sb.toString();
    }

    private static int digit(char c) {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    }

    private static String quote(String s) {
        return s.length() > 40 ? s.substring(0, 40) + "..." : s;
    }

    /** 格式损坏：与预算耗尽、语义无解严格区分。 */
    public static final class FormatException extends RuntimeException {
        public FormatException(String message) { super(message); }
    }
}
