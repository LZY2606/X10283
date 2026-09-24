package quiccourt.core;

/** Result status of any computed node. The three failure families
 *  (resource, format, semantic) are deliberately distinct values. */
public enum Status {
    OK,
    INCOMPLETE_INPUT,     // required input missing: diagnostics carry positions
    FORMAT_CORRUPT,       // bytes/JSON/digest do not parse or verify
    SEMANTIC_UNSOLVABLE,  // parsed fine, but no unique legal answer (incl. conflicts)
    BUDGET_EXHAUSTED      // resource budget ran out before completion
}
