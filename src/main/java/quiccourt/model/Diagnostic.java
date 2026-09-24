package quiccourt.model;

/** A positioned diagnostic. Never silently dropped; incomplete input yields these. */
public record Diagnostic(String code, String severity, String position, String message) {
    public static Diagnostic error(String code, String position, String message) {
        return new Diagnostic(code, "error", position, message);
    }
    public static Diagnostic warn(String code, String position, String message) {
        return new Diagnostic(code, "warn", position, message);
    }
}
