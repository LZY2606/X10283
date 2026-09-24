package org.quiccourt.engine;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import org.quiccourt.domain.Material;
import org.quiccourt.domain.Params;

/**
 * Truncated packet number recovery (RFC 9000 Appendix A.10), per packet number
 * space and direction, retaining multiple legal candidates.
 *
 * <p>Multiplicity arises from two real uncertainties:
 * <ol>
 *   <li><b>PN length field uncertain</b> — until a header-protection candidate
 *       is adopted, the low two bits of byte 0 are untrusted, so lengths
 *       1..available trailing bytes are enumerated;</li>
 *   <li><b>Undecryptable epoch</b> — an unprotected packet cannot be placed in
 *       a unique 2^pnBits epoch, so every congruent value inside the recovery
 *       window is retained.</li>
 * </ol>
 *
 * <p>Outcomes kept distinct: UNIQUE, AMBIGUOUS, BUDGET_EXHAUSTED and
 * SEMANTIC_NO_SOLUTION.
 */
public final class PnRecovery {

    private PnRecovery() {
    }

    /** Mutable per-(space,direction) recovery state. */
    public static final class State {
        public long largestConfirmed = -1;
        public boolean bootstrapped = false;
        public final Set<Long> confirmed = new LinkedHashSet<>();
        public final Set<Long> holes = new TreeSet<>();
    }

    /** Result of one header analysis, before content-addressing. */
    public static final class Outcome {
        public final ResultStatus status;
        public final List<Candidate> candidates;
        public final Long adopted;
        public final long anchor;
        public final String note;
        public final List<Integer> enumeratedLengths;

        Outcome(ResultStatus status, List<Candidate> candidates, Long adopted, long anchor,
                String note, List<Integer> enumeratedLengths) {
            this.status = status;
            this.candidates = candidates;
            this.adopted = adopted;
            this.anchor = anchor;
            this.note = note;
            this.enumeratedLengths = enumeratedLengths;
        }
    }

    public static Outcome process(Material.Header h, State st, Params params) {
        List<Integer> lengths = candidateLengths(h);
        boolean decryptable = h.decryptable;

        if (!st.bootstrapped) {
            return bootstrap(h, lengths, decryptable, st, params);
        }

        long expected = st.largestConfirmed;
        TreeSet<Long> values = new TreeSet<>();
        boolean truncated = false;
        long totalLegal = 0;
        for (int len : lengths) {
            long pnWin = 1L << (len * 8);
            long hwin = pnWin / params.pnWindowDivisor;
            long tv = suffixValue(h.truncatedPnHex, len);
            totalLegal += countInWindow(tv, pnWin, expected, hwin);
            List<Long> v = valuesInWindow(tv, pnWin, expected, hwin,
                    params.pnMaxCandidates - values.size());
            values.addAll(v);
            if (totalLegal > params.pnMaxCandidates) {
                truncated = true;
            }
        }

        String windowNote = "anchor=" + expected
                + " enumeratedLengths=" + lengths
                + " windowDivisor=/" + params.pnWindowDivisor;

        if (decryptable) {
            Long adopted = values.size() == 1 ? values.first() : null;
            if (values.isEmpty()) {
                return new Outcome(ResultStatus.SEMANTIC_NO_SOLUTION, List.of(), null,
                        st.largestConfirmed,
                        "decrypted packet but no length/epoch lands in the recovery window. "
                                + windowNote, lengths);
            }
            if (!st.confirmed.contains(adopted != null ? adopted : values.first())) {
                long v = adopted != null ? adopted : values.first();
                st.confirmed.add(v);
                if (v > st.largestConfirmed) {
                    st.largestConfirmed = v;
                }
            }
            if (values.size() > 1) {
                return new Outcome(ResultStatus.AMBIGUOUS, candidates(values, null), null,
                        st.largestConfirmed,
                        "decrypted but PN length is unconfirmed (header protection candidate "
                                + "unresolved): " + values.size() + " legal decodes retained. "
                                + windowNote, lengths);
            }
            return new Outcome(ResultStatus.UNIQUE, candidates(values, adopted), adopted,
                    st.largestConfirmed,
                    "RFC A.10 unique decode after successful decryption. " + windowNote, lengths);
        }

        if (values.isEmpty()) {
            return new Outcome(ResultStatus.SEMANTIC_NO_SOLUTION, List.of(), null,
                    st.largestConfirmed,
                    "undecryptable hole: no full packet number is congruent to the truncated "
                            + "bytes inside the recovery window for any candidate length. "
                            + windowNote, lengths);
        }
        st.holes.addAll(values);
        if (truncated) {
            return new Outcome(ResultStatus.BUDGET_EXHAUSTED, candidates(values, null), null,
                    st.largestConfirmed,
                    "undecryptable hole: legal-candidate count exceeds budget "
                            + params.pnMaxCandidates + "; enumeration truncated. " + windowNote,
                    lengths);
        }
        if (values.size() > 1) {
            return new Outcome(ResultStatus.AMBIGUOUS, candidates(values, null), null,
                    st.largestConfirmed,
                    "undecryptable hole: " + values.size()
                            + " legal full packet numbers retained; none is adopted without "
                            + "successful decryption. " + windowNote, lengths);
        }
        return new Outcome(ResultStatus.AMBIGUOUS,
                List.of(new Candidate(String.valueOf(values.first()), false,
                        "single consistent value, but unconfirmed: packet never decrypted")),
                null, st.largestConfirmed,
                "undecryptable hole: one consistent value but it is not adopted. "
                        + windowNote, lengths);
    }

    private static Outcome bootstrap(Material.Header h, List<Integer> lengths,
                                     boolean decryptable, State st, Params params) {
        String note0 = "no anchor yet; enumeratedLengths=" + lengths
                + " preAnchorEpochBudget=" + params.preAnchorEpochs;
        if (decryptable && lengths.size() == 1) {
            long v = suffixValue(h.truncatedPnHex, lengths.get(0));
            st.bootstrapped = true;
            st.largestConfirmed = v;
            st.confirmed.add(v);
            return new Outcome(ResultStatus.UNIQUE,
                    List.of(new Candidate(String.valueOf(v), true,
                            "first decrypted packet anchors at its decoded value")),
                    v, 0,
                    "bootstrap anchor: first decrypted PN anchors the space. " + note0, lengths);
        }
        TreeSet<Long> values = new TreeSet<>();
        long total = 0;
        boolean truncated = false;
        for (int len : lengths) {
            long pnWin = 1L << (len * 8);
            long tv = suffixValue(h.truncatedPnHex, len);
            for (long k = 0; k < params.preAnchorEpochs && values.size() < params.pnMaxCandidates;
                 k++) {
                values.add(k * pnWin + tv);
                total++;
            }
            if (values.size() >= params.pnMaxCandidates
                    || params.preAnchorEpochs * lengths.size() > params.pnMaxCandidates) {
                truncated = true;
            }
        }
        if (truncated) {
            return new Outcome(ResultStatus.BUDGET_EXHAUSTED, candidates(values, null), null, -1,
                    "pre-anchor hole: legal epochs exceed the candidate budget; enumeration "
                            + "truncated. " + note0, lengths);
        }
        if (decryptable && values.size() == 1) {
            long v = values.first();
            st.bootstrapped = true;
            st.largestConfirmed = v;
            st.confirmed.add(v);
            return new Outcome(ResultStatus.UNIQUE, candidates(values, v), v, 0,
                    "bootstrap anchor resolved uniquely after decryption. " + note0, lengths);
        }
        String why = decryptable
                ? "decrypted but PN length unconfirmed, so anchor cannot be fixed"
                : "packet never decrypted; no anchor exists yet";
        return new Outcome(ResultStatus.AMBIGUOUS, candidates(values, null), null, -1,
                "pre-anchor hole: " + values.size() + " legal epochs retained (" + why + "). "
                        + note0, lengths);
    }

    /** Candidate PN lengths: declared length, or 1..trailing-byte count. */
    public static List<Integer> candidateLengths(Material.Header h) {
        if (h.pnBytes != null) {
            return List.of(h.pnBytes);
        }
        int available = h.truncatedPnHex.length() / 2;
        int max = Math.min(4, available);
        List<Integer> out = new ArrayList<>();
        for (int len = 1; len <= max; len++) {
            out.add(len);
        }
        return out;
    }

    /** Value of the last {@code len} bytes of the trailing-bytes hex string. */
    static long suffixValue(String trailingHex, int len) {
        String suffix = trailingHex.substring(trailingHex.length() - len * 2);
        return Long.parseLong(suffix, 16);
    }

    /** RFC 9000 A.10 nearest-to-expected decode for one length. */
    public static long rfcDecode(long truncated, int pnBits, long expected, long windowDivisor) {
        long pnWin = 1L << pnBits;
        long hwin = pnWin / windowDivisor;
        long mask = pnWin - 1;
        long candidate = (expected & ~mask) | truncated;
        if (candidate <= expected - hwin) {
            candidate += pnWin;
        } else if (candidate > expected + hwin && candidate - pnWin >= 0) {
            candidate -= pnWin;
        }
        return candidate;
    }

    private static long countInWindow(long truncated, long pnWin, long expected, long hwin) {
        long lo = Math.max(0, expected - hwin);
        long hi = expected + hwin;
        long firstK = lo > truncated ? (lo - truncated + pnWin - 1) / pnWin : 0;
        if (hi < truncated) {
            return 0;
        }
        long lastK = (hi - truncated) / pnWin;
        return Math.max(0, lastK - firstK + 1);
    }

    private static List<Long> valuesInWindow(long truncated, long pnWin, long expected,
                                             long hwin, long limit) {
        long lo = Math.max(0, expected - hwin);
        long hi = expected + hwin;
        long firstK = lo > truncated ? (lo - truncated + pnWin - 1) / pnWin : 0;
        List<Long> out = new ArrayList<>();
        for (long k = firstK; out.size() < limit; k++) {
            long v = k * pnWin + truncated;
            if (v > hi) {
                break;
            }
            out.add(v);
        }
        return out;
    }

    private static List<Candidate> candidates(Set<Long> values, Long adopted) {
        List<Candidate> out = new ArrayList<>();
        for (long v : values) {
            out.add(new Candidate(String.valueOf(v), adopted != null && adopted == v,
                    "congruent to truncated PN bytes inside recovery window"));
        }
        return out;
    }
}
