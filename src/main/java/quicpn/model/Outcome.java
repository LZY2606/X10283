package quicpn.model;

/**
 * Result classification. Resource budget exhaustion, corrupt formats and
 * semantic dead-ends are three distinct outcomes, never collapsed into nulls.
 */
public enum Outcome {
    OK,
    BUDGET_EXHAUSTED,
    FORMAT_CORRUPT,
    SEMANTIC_UNSOLVABLE
}
