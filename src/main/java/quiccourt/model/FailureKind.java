package quiccourt.model;

/** Three mutually exclusive failure classes. Equivalent inputs must map to a stable one. */
public enum FailureKind {
    BUDGET_EXHAUSTED,
    FORMAT_CORRUPT,
    SEMANTIC_UNSOLVABLE
}
