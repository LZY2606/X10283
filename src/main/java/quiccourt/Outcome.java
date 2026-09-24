package quiccourt;

import java.util.List;

/**
 * Rule outcome. The three failure modes are distinct results, never collapsed:
 * BUDGET_EXHAUSTED (resource budget), FORMAT_CORRUPT (bad encoding), SEMANTIC_UNSOLVABLE (no legal answer).
 */
public record Outcome<T>(Status status, T value, List<Diag> diags) {
    public enum Status { OK, BUDGET_EXHAUSTED, FORMAT_CORRUPT, SEMANTIC_UNSOLVABLE }

    public static <T> Outcome<T> ok(T v) { return new Outcome<>(Status.OK, v, List.of()); }
    public static <T> Outcome<T> fail(Status s, List<Diag> d) { return new Outcome<>(s, null, d); }
}
