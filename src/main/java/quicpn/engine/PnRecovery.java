package quicpn.engine;

import java.util.ArrayList;
import java.util.List;
import quicpn.model.Diagnostic;
import quicpn.model.Outcome;

/**
 * Truncated packet-number recovery (RFC 9000 appendix A.3) extended to keep
 * every legitimate candidate inside the ambiguity window instead of silently
 * committing to one. Deterministic ordering: candidates sorted by value, the
 * primary is the RFC-decoded value when state exists, otherwise the smallest.
 */
public final class PnRecovery {
    public static final long MAX_PN = (1L << 62) - 1;

    public record Candidate(long value, String role) {}

    public record Result(Outcome outcome, List<Candidate> candidates, List<Diagnostic> diagnostics) {
        public long primary() {
            for (Candidate c : candidates) if (c.role().equals("PRIMARY")) return c.value();
            return candidates.isEmpty() ? -1 : candidates.get(0).value();
        }
    }

    private PnRecovery() {}

    /** RFC 9000 A.3 decode of a truncated packet number. */
    public static long decodeTruncated(long expected, long truncated, int nbits) {
        long window = 1L << nbits;
        long half = window / 2;
        long mask = window - 1;
        long candidate = (expected & ~mask) | truncated;
        if (candidate + half <= expected && candidate + window <= MAX_PN) return candidate + window;
        if (candidate > expected + half && candidate >= window) return candidate - window;
        return candidate;
    }

    /**
     * Recover a full packet number.
     *
     * @param truncated the truncated packet number as carried on the wire
     * @param nbits     number of bits of the truncated field (1..62)
     * @param expected  expected next packet number (largest known + 1), or null when
     *                  state is missing (e.g. after an undecryptable gap): then every
     *                  window-congruent candidate is retained up to {@code budget}
     * @param budget    maximum number of candidates to enumerate; exceeding it yields
     *                  BUDGET_EXHAUSTED, never a truncated silent answer
     */
    public static Result recover(long truncated, int nbits, Long expected, int budget) {
        List<Diagnostic> diags = new ArrayList<>();
        List<Candidate> candidates = new ArrayList<>();
        if (nbits < 1 || nbits > 62) {
            diags.add(new Diagnostic("packet/pn_nbits", "format.corrupt",
                    "pn_nbits=" + nbits + " 超出合法区间 [1,62]"));
            return new Result(Outcome.FORMAT_CORRUPT, candidates, diags);
        }
        long window = 1L << nbits;
        if (truncated < 0 || truncated >= window) {
            diags.add(new Diagnostic("packet/truncated_pn", "format.corrupt",
                    "truncated_pn=" + truncated + " 与 pn_nbits=" + nbits + " 不一致"));
            return new Result(Outcome.FORMAT_CORRUPT, candidates, diags);
        }
        if (expected != null) {
            long primary = decodeTruncated(expected, truncated, nbits);
            candidates.add(new Candidate(primary, "PRIMARY"));
            // Retain the neighbouring window solutions as alternates: the window
            // keeps multiple readings alive instead of collapsing them.
            if (primary - window >= 0) candidates.add(new Candidate(primary - window, "ALTERNATE"));
            if (primary + window <= MAX_PN) candidates.add(new Candidate(primary + window, "ALTERNATE"));
        } else {
            long value = truncated;
            int count = 0;
            while (value <= MAX_PN) {
                if (count >= budget) {
                    diags.add(new Diagnostic("packet/truncated_pn", "budget.exhausted",
                            "无状态窗口枚举超过预算 budget=" + budget + "，候选被截断于 pn=" + value));
                    return new Result(Outcome.BUDGET_EXHAUSTED, candidates, diags);
                }
                candidates.add(new Candidate(value, count == 0 ? "PRIMARY" : "ALTERNATE"));
                count++;
                value += window;
            }
        }
        candidates.sort((a, b) -> {
            int r = a.role().compareTo(b.role());
            return r != 0 ? r : Long.compare(a.value(), b.value());
        });
        return new Result(Outcome.OK, candidates, diags);
    }
}
