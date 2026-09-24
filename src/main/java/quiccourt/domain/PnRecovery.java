package quiccourt.domain;

import java.util.ArrayList;
import java.util.List;

/**
 * RFC 9000 Appendix A.3 truncated packet number decoding.
 *
 * <p>When the largest acknowledged/received packet number is confident, the decode is
 * unique inside the truncation window. When an undecryptable gap precedes the packet
 * (largest PN is stale by an unknown number of windows), the window admits multiple
 * legal candidates and all of them are retained instead of silently picking one.
 */
public final class PnRecovery {

    public enum Status { RECOVERED_UNIQUE, RECOVERED_AMBIGUOUS }

    public record Result(Status status, long recovered, List<Long> candidates) {}

    /**
     * @param largest   largest confidently recovered PN in this space so far (or -1)
     * @param truncated truncated packet number as on the wire
     * @param pnBits    number of bits of the truncated field
     * @param gapBefore true when an undecryptable gap makes {@code largest} stale
     */
    public static Result decode(long largest, long truncated, int pnBits, boolean gapBefore) {
        long win = 1L << pnBits;
        long hwin = win >> 1;
        long mask = win - 1;
        long expected = largest + 1;
        long candidate = (expected & ~mask) | truncated;
        if (candidate + hwin <= expected) {
            candidate += win;
        } else if (candidate - hwin > expected && candidate >= win) {
            candidate -= win;
        }
        List<Long> candidates = new ArrayList<>();
        candidates.add(candidate);
        if (gapBefore) {
            // An unknown number of windows may have elapsed inside the gap: every
            // congruent value above the stale largest is a legal candidate.
            long c = candidate;
            while (c <= largest) c += win;
            candidates.clear();
            candidates.add(c);
            candidates.add(c + win);
            return new Result(Status.RECOVERED_AMBIGUOUS, c, List.copyOf(candidates));
        }
        return new Result(Status.RECOVERED_UNIQUE, candidate, List.copyOf(candidates));
    }

    private PnRecovery() {}
}
