package quiccourt.core;

/** Counted operation budget. Exhaustion is a first-class result, not an exception. */
public final class Budget {
    private long remaining;
    public Budget(long maxOps) { this.remaining = maxOps; }
    public boolean spend(long ops) {
        if (ops <= remaining) { remaining -= ops; return true; }
        remaining = 0;
        return false;
    }
    public boolean spendOne() { return spend(1); }
    public long remaining() { return remaining; }
}
