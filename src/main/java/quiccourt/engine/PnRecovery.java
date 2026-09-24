package quiccourt.engine;

import java.util.ArrayList;
import java.util.List;

/** Truncated packet-number recovery per RFC 9000 Appendix A.3, extended to keep
 *  every legal candidate inside the reconstruction window (window multi-solution). */
public final class PnRecovery {
    private PnRecovery() {}

    public static final long MAX_PN = (1L << 62) - 1;

    public record Candidate(long fullPn, String rationale, boolean primary) {}

    public record Result(List<Candidate> candidates, long window, long expectedPn) {
        public boolean unique() { return candidates.size() == 1; }
    }

    /**
     * @param expectedPn  next expected packet number (largest seen + 1) in this space
     * @param truncatedPn the truncated packet number from the wire
     * @param pnBits      number of bits carried on the wire
     */
    public static Result recover(long expectedPn, long truncatedPn, int pnBits) {
        long window = 1L << pnBits;
        long hwin = window / 2;
        long mask = window - 1;
        long candidate = (expectedPn & ~mask) | truncatedPn;

        List<Candidate> out = new ArrayList<>();
        long primary;
        if (candidate <= expectedPn - hwin && candidate < MAX_PN - window) {
            primary = candidate + window;
        } else if (candidate > expectedPn + hwin && candidate >= window) {
            primary = candidate - window;
        } else {
            primary = candidate;
        }
        out.add(new Candidate(primary, "rfc9000-A.3 nearest to expected_pn=" + expectedPn, true));

        // Keep alternative in-window reconstructions instead of collapsing to one answer.
        long above = primary + window;
        if (above <= MAX_PN && Math.abs(above - expectedPn) <= hwin)
            out.add(new Candidate(above, "window alternative +2^" + pnBits + " still inside +/-2^" + (pnBits - 1), false));
        long below = primary - window;
        if (below >= 0 && Math.abs(below - expectedPn) <= hwin)
            out.add(new Candidate(below, "window alternative -2^" + pnBits + " still inside +/-2^" + (pnBits - 1), false));

        out.sort((a, b) -> Long.compare(a.fullPn(), b.fullPn()));
        return new Result(out, window, expectedPn);
    }
}
