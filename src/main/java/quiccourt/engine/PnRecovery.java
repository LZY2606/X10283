package quiccourt.engine;

import java.util.ArrayList;
import java.util.List;

/**
 * Truncated packet number recovery (RFC 9000 appendix A.3 basis), extended to keep
 * every candidate inside a widened ambiguity window instead of collapsing to one.
 * Packet number spaces (Initial / Handshake / Application) are tracked in isolation.
 */
public final class PnRecovery {

    public record Recovery(long expectedNext, long truncated, int pnBits,
                           long windowLo, long windowHi,
                           List<Long> candidates, long rfcPreferred) {}

    /** RFC 9000 A.3 single-value decode. */
    public static long decode(long expectedNext, long truncated, int pnBits) {
        long pnNbits = 1L << pnBits;
        long pnHalf = pnNbits >>> 1;
        long pnMask = pnNbits - 1;
        long candidate = (expectedNext & ~pnMask) | truncated;
        if (candidate + pnHalf <= expectedNext && candidate + pnNbits < (1L << 62))
            return candidate + pnNbits;
        if (candidate > expectedNext + pnHalf && candidate >= pnNbits)
            return candidate - pnNbits;
        return candidate;
    }

    /**
     * All values congruent to {@code truncated} mod 2^pnBits inside the window
     * [expectedNext - half - extra, expectedNext + half + extra), clamped at 0,
     * where extra = ambiguityWindows * 2^pnBits. Sorted ascending for stable order.
     */
    public static Recovery recover(long expectedNext, long truncated, int pnBits, int ambiguityWindows) {
        long pnNbits = 1L << pnBits;
        long pnHalf = pnNbits >>> 1;
        long extra = (long) ambiguityWindows * pnNbits;
        long lo = Math.max(0, expectedNext - pnHalf - extra);
        long hi = expectedNext + pnHalf + extra;
        List<Long> out = new ArrayList<>();
        long first = lo + Math.floorMod(truncated - lo, pnNbits);
        for (long v = first; v < hi; v += pnNbits) out.add(v);
        return new Recovery(expectedNext, truncated, pnBits, lo, hi,
                List.copyOf(out), decode(expectedNext, truncated, pnBits));
    }
}
