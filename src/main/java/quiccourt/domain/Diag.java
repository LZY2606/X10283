package quiccourt.domain;

/**
 * A typed diagnostic. {@code code} is one of the mandated machine-readable result kinds:
 * INCOMPLETE_INPUT, FORMAT_CORRUPT, SEMANTIC_UNSOLVABLE, BUDGET_EXHAUSTED are three
 * distinct failure results (plus UNIT_UNCONVERTIBLE for raw values that cannot be
 * normalized into the derived layer). {@code pos} locates the offending input.
 */
public record Diag(String code, String pos, String message) {
    public static final String INCOMPLETE_INPUT = "INCOMPLETE_INPUT";
    public static final String FORMAT_CORRUPT = "FORMAT_CORRUPT";
    public static final String SEMANTIC_UNSOLVABLE = "SEMANTIC_UNSOLVABLE";
    public static final String BUDGET_EXHAUSTED = "BUDGET_EXHAUSTED";
    public static final String UNIT_UNCONVERTIBLE = "UNIT_UNCONVERTIBLE";

    public static Diag incomplete(String pos, String msg) { return new Diag(INCOMPLETE_INPUT, pos, msg); }
    public static Diag corrupt(String pos, String msg) { return new Diag(FORMAT_CORRUPT, pos, msg); }
    public static Diag unsolvable(String pos, String msg) { return new Diag(SEMANTIC_UNSOLVABLE, pos, msg); }
    public static Diag budget(String pos, String msg) { return new Diag(BUDGET_EXHAUSTED, pos, msg); }
    public static Diag unit(String pos, String msg) { return new Diag(UNIT_UNCONVERTIBLE, pos, msg); }
}
