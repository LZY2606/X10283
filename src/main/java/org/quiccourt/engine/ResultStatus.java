package org.quiccourt.engine;

/** Status of a derived object. The three failure classes are kept distinct. */
public enum ResultStatus {
    UNIQUE,
    AMBIGUOUS,                 // multiple legal candidates retained
    BUDGET_EXHAUSTED,          // resource budget spent
    FORMAT_CORRUPT,            // malformed material
    SEMANTIC_NO_SOLUTION,      // well-formed but no legal solution
    REJECTED_MISFLIP,          // key phase flip not confirmed
    REJECTED_EXPIRED,          // old key used past grace
    COMMITTED,                 // key update committed
    UPDATE_DETECTED,           // first new-key packet, awaiting confirmation
    CONFIRMED,
    ACCEPTED,
    UNVERIFIABLE,              // ACK covers undecryptable hole
    ISOLATED,
    MIGRATED,
    CONTINUOUS,
    UNISSUED_CID,
    REPLAYED_OK
}
