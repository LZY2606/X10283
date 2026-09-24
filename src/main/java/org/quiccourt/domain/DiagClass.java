package org.quiccourt.domain;

/**
 * The three required, distinct failure outcomes.
 *
 * <ul>
 *   <li>{@link #BUDGET_EXHAUSTED} — resource budget spent (e.g. candidate cap).</li>
 *   <li>{@link #FORMAT_CORRUPT} — the material itself is malformed/unparseable.</li>
 *   <li>{@link #SEMANTIC_NO_SOLUTION} — well-formed input but no legal solution.</li>
 * </ul>
 */
public enum DiagClass {
    BUDGET_EXHAUSTED,
    FORMAT_CORRUPT,
    SEMANTIC_NO_SOLUTION;

    public String code() {
        return name();
    }
}
