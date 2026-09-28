package quiccourt.domain;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;

/**
 * 横切类型：结果三态（成功 / 资源预算耗尽 / 格式损坏 / 语义无解）、
 * 带位置的诊断、内容哈希与稳定身份工具。
 */
public final class Common {

    private Common() {
    }

    /** 资源预算耗尽、格式损坏、语义无解必须是三种不同结果，成功是第四种。 */
    public enum OutcomeKind {
        SUCCESS,
        BUDGET_EXHAUSTED,
        FORMAT_CORRUPT,
        SEMANTIC_UNRESOLVABLE
    }

    public enum Severity {
        ERROR, WARNING, INFO
    }

    /** 定位到具体输入片段的诊断；输入不完整时绝不以默认值伪装成功。 */
    public record Diagnostic(String code, Severity severity, String position, String message) {
        public static Diagnostic error(String code, String position, String message) {
            return new Diagnostic(code, Severity.ERROR, position, message);
        }

        public static Diagnostic warning(String code, String position, String message) {
            return new Diagnostic(code, Severity.WARNING, position, message);
        }
    }

    public record Outcome<T>(OutcomeKind kind, T value, List<Diagnostic> diagnostics) {
        public boolean ok() {
            return kind == OutcomeKind.SUCCESS;
        }

        public static <T> Outcome<T> success(T value) {
            return new Outcome<>(OutcomeKind.SUCCESS, value, List.of());
        }

        public static <T> Outcome<T> success(T value, List<Diagnostic> diags) {
            return new Outcome<>(OutcomeKind.SUCCESS, value, diags);
        }

        public static <T> Outcome<T> failure(OutcomeKind kind, List<Diagnostic> diags) {
            if (kind == OutcomeKind.SUCCESS) {
                throw new IllegalArgumentException("failure needs a non-success kind");
            }
            return new Outcome<>(kind, null, diags);
        }

        public static <T> Outcome<T> failure(OutcomeKind kind, Diagnostic diag) {
            return failure(kind, List.of(diag));
        }

        public String joinMessages() {
            List<String> parts = new ArrayList<>();
            for (Diagnostic d : diagnostics) {
                parts.add("[" + d.position + "] " + d.code + ": " + d.message);
            }
            return String.join("; ", parts);
        }
    }

    /** 领域量的单位/坐标基准：所有领域量都携带单位或坐标基准。 */
    public record UnitBasis(String dimension, String unit, String origin) {
        public static final UnitBasis BYTES = new UnitBasis("length", "byte", "datagram[0]");
        public static final UnitBasis PACKETS = new UnitBasis("packet_number", "packet", "space origin");
        public static final UnitBasis MICROS = new UnitBasis("time", "microsecond", "capture t0");
        public static final UnitBasis MILLIS = new UnitBasis("time", "millisecond", "capture t0");
    }

    public static String sha256Hex(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(input.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder(64);
            for (byte b : digest) {
                sb.append(Character.forDigit((b >> 4) & 0xF, 16));
                sb.append(Character.forDigit(b & 0xF, 16));
            }
            return sb.toString();
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    public static String shortHash(String input) {
        String hex = sha256Hex(input);
        return hex.substring(0, 12);
    }

    /** 稳定身份：前缀 + 内容摘要短哈希。 */
    public static String stableId(String prefix, String content) {
        return prefix + "_" + shortHash(content);
    }
}
