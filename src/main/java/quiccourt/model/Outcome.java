package quiccourt.model;

import java.util.List;

/** Result of a computation: either a value, or a classified failure with positioned diagnostics. */
public record Outcome<T>(T value, FailureKind failure, List<Diagnostic> diagnostics) {
    public static <T> Outcome<T> ok(T value) { return new Outcome<>(value, null, List.of()); }
    public static <T> Outcome<T> ok(T value, List<Diagnostic> diags) { return new Outcome<>(value, null, diags); }
    public static <T> Outcome<T> fail(FailureKind kind, List<Diagnostic> diags) { return new Outcome<>(null, kind, diags); }
    public boolean isOk() { return failure == null; }
}
