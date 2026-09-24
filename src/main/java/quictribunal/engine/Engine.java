package quictribunal.engine;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import quictribunal.json.Json;
import quictribunal.model.Domain;
import quictribunal.model.Domain.AckRange;
import quictribunal.model.Domain.CidEvent;
import quictribunal.model.Domain.Computation;
import quictribunal.model.Domain.Datagram;
import quictribunal.model.Domain.Decision;
import quictribunal.model.Domain.Diagnostic;
import quictribunal.model.Domain.Direction;
import quictribunal.model.Domain.Event;
import quictribunal.model.Domain.HpCandidate;
import quictribunal.model.Domain.KeyGen;
import quictribunal.model.Domain.Packet;
import quictribunal.model.Domain.PathInfo;
import quictribunal.model.Domain.PnSpace;
import quictribunal.model.Domain.RuleParams;
import quictribunal.model.Ids;

/**
 * Server-side QUIC review engine. Pure functions ({@link #recoverPacketNumber},
 * {@link #parseAckFrame}) are directly unit-testable; {@link #replay} rebuilds the full
 * structured state from the append-only event log, so every historical conclusion can be
 * reproduced exactly.
 */
public final class Engine {
    private Engine() {}

    // ------------------------------------------------------------- hex/varint

    public static byte[] hex(String s) {
        if (s == null || (s.length() % 2) != 0) {
            throw new IllegalArgumentException("hex string must have even length");
        }
        byte[] out = new byte[s.length() / 2];
        for (int i = 0; i < out.length; i++) {
            int hi = Character.digit(s.charAt(i * 2), 16);
            int lo = Character.digit(s.charAt(i * 2 + 1), 16);
            if (hi < 0 || lo < 0) throw new IllegalArgumentException("bad hex digit");
            out[i] = (byte) ((hi << 4) | lo);
        }
        return out;
    }

    public static String hex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) sb.append(String.format("%02x", b));
        return sb.toString();
    }

    public record VarintRead(long value, int nextOffset, Diagnostic error) {}

    /** Reads a QUIC variable-length integer (RFC 9000 16) starting at {@code off}. */
    public static VarintRead readVarint(byte[] buf, int off, String path) {
        if (off >= buf.length) {
            return new VarintRead(0, off, Diagnostic.format("VARINT_TRUNCATED", path,
                    off, "varint runs past end of buffer"));
        }
        int first = buf[off] & 0xff;
        int lenCode = first >>> 6;
        int len = switch (lenCode) {
            case 0 -> 1;
            case 1 -> 2;
            case 2 -> 4;
            case 3 -> 8;
            default -> 1;
        };
        if (off + len > buf.length) {
            return new VarintRead(0, off, Diagnostic.format("VARINT_TRUNCATED", path,
                    off, len + "-byte varint runs past end of buffer"));
        }
        long value = first & 0x3f;
        for (int i = 1; i < len; i++) value = (value << 8) | (buf[off + i] & 0xff);
        return new VarintRead(value, off + len, null);
    }

    // ---------------------------------------------------------- ACK frames

    public record AckRead(long largest, long ackDelayNs, List<AckRange> ranges,
                          int consumed, List<Diagnostic> errors) {}

    /**
     * Parses an ACK frame (RFC 9000 19.3). The first byte must be 0x02. Ranges are returned in
     * ascending order. Every structural fault carries an offset inside the frame.
     */
    public static AckRead parseAckFrame(byte[] frame, String path) {
        List<Diagnostic> errors = new ArrayList<>();
        if (frame.length == 0) {
            errors.add(Diagnostic.format("ACK_EMPTY", path, 0, "empty ACK frame"));
            return new AckRead(0, 0, List.of(), 0, errors);
        }
        if ((frame[0] & 0xff) != 0x02) {
            errors.add(Diagnostic.format("ACK_WRONG_TYPE", path, 0,
                    "expected ACK frame type 0x02, got 0x" + String.format("%02x", frame[0])));
            return new AckRead(0, 0, List.of(), 1, errors);
        }
        int off = 1;
        VarintRead largest = readVarint(frame, off, path + ":largest_acknowledged");
        if (largest.error != null) { errors.add(largest.error); return fail(errors); }
        off = largest.nextOffset;
        VarintRead delay = readVarint(frame, off, path + ":ack_delay");
        if (delay.error != null) { errors.add(delay.error); return fail(errors); }
        off = delay.nextOffset;
        VarintRead rangeCount = readVarint(frame, off, path + ":ack_range_count");
        if (rangeCount.error != null) { errors.add(rangeCount.error); return fail(errors); }
        off = rangeCount.nextOffset;
        if (rangeCount.value > 1_000_000L) {
            errors.add(Diagnostic.format("ACK_RANGE_COUNT_ABSURD", path,
                    rangeCount.nextOffset - 8, "ack_range_count implausible"));
            return fail(errors);
        }
        VarintRead firstRange = readVarint(frame, off, path + ":first_ack_range");
        if (firstRange.error != null) { errors.add(firstRange.error); return fail(errors); }
        off = firstRange.nextOffset;

        List<AckRange> ascending = new ArrayList<>();
        long prevSmallest = largest.value - firstRange.value;
        if (prevSmallest < 0) {
            errors.add(new Diagnostic("ACK_RANGE_NEGATIVE", Domain.Outcome.SEMANTIC_UNSOLVABLE,
                    path + ":first_ack_range", null, null,
                    "first_ack_range extends below packet number 0"));
            return fail(errors);
        }
        ascending.add(new AckRange(prevSmallest, largest.value));
        for (long i = 0; i < rangeCount.value; i++) {
            VarintRead gap = readVarint(frame, off, path + ":gap[" + i + "]");
            if (gap.error != null) { errors.add(gap.error); return fail(errors); }
            off = gap.nextOffset;
            VarintRead rangeLen = readVarint(frame, off, path + ":range_len[" + i + "]");
            if (rangeLen.error != null) { errors.add(rangeLen.error); return fail(errors); }
            off = rangeLen.nextOffset;
            long upper = prevSmallest - gap.value - 2;
            long lower = upper - rangeLen.value;
            if (gap.value < 0 || upper < 0 || lower < 0 || lower > upper) {
                errors.add(new Diagnostic("ACK_RANGE_INCONSISTENT",
                        Domain.Outcome.SEMANTIC_UNSOLVABLE, path + ":range[" + i + "]",
                        null, null, "ACK range/gap produces negative or inverted interval"));
                return fail(errors);
            }
            ascending.add(0, new AckRange(lower, upper));
            prevSmallest = lower;
        }
        return new AckRead(largest.value, delay.value, List.copyOf(ascending), off, errors);
    }

    private static AckRead fail(List<Diagnostic> errors) {
        return new AckRead(0, 0, List.of(), 0, errors);
    }

    // ------------------------------------------------- packet number recovery

    public enum PnStatus { UNIQUE, WRAPPED, AMBIGUOUS, UNSOLVABLE }

    public record PnResult(long expected, long truncated, int pnLen,
                           long window, long standard, List<Long> candidates,
                           PnStatus status, String note) {}

    /**
     * Truncated packet number recovery after RFC 9000 Appendix A.3, with one difference forced by
     * this tribunal: when the observation lies exactly on the half-window boundary the standard
     * choice is not provably unique, so every legal candidate congruent modulo 2^pnLen within the
     * recovery window is retained and the result is marked AMBIGUOUS.
     */
    public static PnResult recoverPacketNumber(long expected, long truncated, int pnLen) {
        if (pnLen < 1 || pnLen > 4) {
            throw new IllegalArgumentException("pnLen must be 1..4 bytes");
        }
        long bits = pnLen * 8L;
        long window = 1L << bits;
        long half = window >>> 1;
        long mask = window - 1;
        if (truncated < 0 || truncated > mask) {
            return new PnResult(expected, truncated, pnLen, window, -1, List.of(),
                    PnStatus.UNSOLVABLE,
                    "truncated packet number " + truncated + " does not fit " + bits + " bits");
        }
        long base = expected & ~mask;
        long standard = base | truncated;
        if (standard <= expected - half) standard += window;
        if (standard > expected + half) standard -= window;

        long low = Math.max(0L, expected - half);
        long high = expected + half;
        List<Long> candidates = new ArrayList<>();
        long first = low + ((truncated - low) & mask);
        for (long v = first; v <= high && v >= first; v += window) {
            candidates.add(v);
            if (v > Long.MAX_VALUE - window) break;
        }
        PnStatus status;
        String note;
        if (candidates.isEmpty()) {
            status = PnStatus.UNSOLVABLE;
            note = "no packet number congruent to " + truncated + " mod 2^" + bits
                    + " inside recovery window [" + low + ", " + high + "]";
        } else if (candidates.size() > 1) {
            status = PnStatus.AMBIGUOUS;
            note = "window boundary: RFC A.3 would pick " + standard
                    + " but " + candidates.size() + " legal candidates remain";
        } else if (standard < expected) {
            status = PnStatus.WRAPPED;
            note = "truncated packet number wrapped the 2^" + bits + " window";
        } else {
            status = PnStatus.UNIQUE;
            note = "single candidate inside recovery window";
        }
        return new PnResult(expected, truncated, pnLen, window, standard,
                List.copyOf(candidates), status, note);
    }
}

    // ----------------------------------------------------------------- replay

    /** Fully reconstructed review state at a point in the (possibly branched) event log. */
    public static final class ReplayState {
        public long atSeq;
        public String branch;
        public String projectId = "";
        public String timeBase = "capture-relative ns (t=0 is capture start)";
        public RuleParams params = RuleParams.v1();
        public int paramsVersion = 1;
        public final List<Datagram> datagrams = new ArrayList<>();
        public final List<Packet> packets = new ArrayList<>();
        public final List<HpCandidate> hpCandidates = new ArrayList<>();
        public final List<KeyGen> keyGens = new ArrayList<>();
        public final List<CidEvent> cidEvents = new ArrayList<>();
        public final List<PathInfo> paths = new ArrayList<>();
        public final List<Decision> decisions = new ArrayList<>();
        public final List<Computation> computations = new ArrayList<>();
        public final List<Diagnostic> diagnostics = new ArrayList<>();
        public Domain.Outcome outcome = Domain.Outcome.OK;
        public long budgetUsed = 0;

        public Packet packet(String id) {
            for (Packet p : packets) if (p.id().equals(id)) return p;
            return null;
        }

        public Datagram datagram(String id) {
            for (Datagram d : datagrams) if (d.id().equals(id)) return d;
            return null;
        }

        /** Derived per-packet findings attached by the engine. */
        public final Map<String, PacketFinding> findings = new LinkedHashMap<>();

        public PacketFinding finding(String packetId) {
            return findings.get(packetId);
        }
    }

    public static final class KeyPhaseVerdict {
        public String status;   // COMMITTED, GRACE_OLD_KEY, MISFLIP_REJECTED, HOLE, NOT_APPLICABLE
        public int observedBit;
        public int phaseBefore;
        public int phaseAfter;
        public long usedGen;
        public String reason;
    }

    public static final class AckFinding {
        public long largest;
        public long ackDelayNs;
        public List<AckRange> ranges = List.of();
        public final List<String> flags = new ArrayList<>();
    }

    public static final class PacketFinding {
        public PnResult pn;
        public String pnComputationId;
        public KeyPhaseVerdict keyPhase;
        public String keyPhaseComputationId;
        public AckFinding ack;
        public String ackComputationId;
        public final List<String> flags = new ArrayList<>();
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> payload(Event e) {
        return (Map<String, Object>) Json.parse(e.payloadJson());
    }

    private static String str(Map<String, Object> m, String key) {
        Object v = m.get(key);
        return v == null ? null : String.valueOf(v);
    }

    private static long lng(Object v) {
        return ((Number) v).longValue();
    }

    private static int intg(Object v) {
        return ((Number) v).intValue();
    }

    /** Selects events visible on a branch: main events up to root, plus branch events. */
    public static List<Event> selectBranch(List<Event> all, String branch, Long untilSeq) {
        List<Event> out = new ArrayList<>();
        for (Event e : all) {
            if (untilSeq != null && e.seq() > untilSeq) continue;
            boolean onMain = e.branch() == null || e.branch().isEmpty();
            if (branch == null || branch.isEmpty() || branch.equals("main")) {
                if (onMain) out.add(e);
            } else {
                if (onMain && (e.rootSeq() == null || e.rootSeq() <= 0)) out.add(e);
                else if (branch.equals(e.branch())) out.add(e);
            }
        }
        out.sort((a, b) -> Long.compare(a.seq(), b.seq()));
        return out;
    }

    public static ReplayState replay(List<Event> events) {
        return replay(events, null, null);
    }

    public static ReplayState replay(List<Event> allEvents, String branch, Long untilSeq) {
        List<Event> events = selectBranch(allEvents, branch, untilSeq);
        ReplayState st = new ReplayState();
        st.branch = branch == null || branch.isEmpty() ? "main" : branch;

        Map<PnSpace, Long> largestPerSpace = new LinkedHashMap<>();
        Map<PnSpace, Long> largestAckedPerSpace = new LinkedHashMap<>();
        Map<PnSpace, Long> lastAckTimeNs = new LinkedHashMap<>();
        Map<Direction, Integer> phase = new LinkedHashMap<>();
        Map<Direction, Long> currentGen = new LinkedHashMap<>();
        Map<Direction, Integer> newKeySuccesses = new LinkedHashMap<>();
        Map<Direction, Long> lastFlipCommitNs = new LinkedHashMap<>();
        for (PnSpace sp : PnSpace.values()) {
            largestPerSpace.put(sp, -1L);
            largestAckedPerSpace.put(sp, -1L);
        }
        phase.put(Direction.C2S, 0);
        phase.put(Direction.S2C, 0);
        currentGen.put(Direction.C2S, 0L);
        currentGen.put(Direction.S2C, 0L);

        for (Event e : events) {
            st.atSeq = e.seq();
            switch (e.type()) {
                case PROJECT_CREATED -> {
                    Map<String, Object> p = payload(e);
                    st.projectId = str(p, "projectId");
                    if (p.get("timeBase") != null) st.timeBase = String.valueOf(p.get("timeBase"));
                }
                case PARAMS_REVISED -> applyParams(st, e);
                case SOURCE_AMENDED -> applyAmend(st, e, largestPerSpace, largestAckedPerSpace,
                        lastAckTimeNs, phase, currentGen, newKeySuccesses, lastFlipCommitNs);
                case MATERIALS_IMPORTED -> applyImport(st, e, largestPerSpace, largestAckedPerSpace,
                        lastAckTimeNs, phase, currentGen, newKeySuccesses, lastFlipCommitNs);
                case DECISION_RECORDED -> st.decisions.add(decisionFromEvent(e));
                case IMPORT_REJECTED, BRANCH_CREATED -> { }
            }
        }
        st.atSeq = events.isEmpty() ? 0 : events.get(events.size() - 1).seq();
        return st;
    }

    private static void applyParams(ReplayState st, Event e) {
        Map<String, Object> p = payload(e);
        long grace = lng(p.get("oldKeyGraceNs"));
        int confirm = intg(p.get("keyUpdateConfirmCount"));
        long reorder = lng(p.get("ackReorderToleranceNs"));
        long budget = lng(p.get("budgetUnits"));
        String label = str(p, "label");
        st.params = new RuleParams(grace, confirm, reorder, budget, label);
        st.paramsVersion = intg(p.get("version"));
    }

    @SuppressWarnings("unchecked")
    private static void applyImport(
            ReplayState st, final Event e,
            Map<PnSpace, Long> largest, Map<PnSpace, Long> largestAcked,
            Map<PnSpace, Long> lastAckTimeNs, Map<Direction, Integer> phase,
            Map<Direction, Long> currentGen, Map<Direction, Integer> newKeySuccesses,
            Map<Direction, Long> lastFlipCommitNs) {
        Map<String, Object> p = payload(e);
        for (Object o : (List<Object>) p.getOrDefault("paths", List.of())) {
            Map<String, Object> m = (Map<String, Object>) o;
            String id = str(m, "id");
            if (st.paths.stream().noneMatch(x -> x.id().equals(id))) {
                st.paths.add(new PathInfo(id, str(m, "fourTuple")));
            }
        }
        for (Object o : (List<Object>) p.getOrDefault("keyGens", List.of())) {
            Map<String, Object> m = (Map<String, Object>) o;
            st.keyGens.add(new KeyGen(str(m, "id"), Domain.KeyRole.valueOf(str(m, "role")),
                    lng(m.get("generation")), lng(m.get("validFromNs")),
                    m.get("validUntilNs") == null ? null : lng(m.get("validUntilNs")),
                    str(m, "secretLabel")));
        }
        for (Object o : (List<Object>) p.getOrDefault("cidEvents", List.of())) {
            Map<String, Object> m = (Map<String, Object>) o;
            st.cidEvents.add(new CidEvent(str(m, "id"), lng(m.get("seq")), str(m, "cidHex"),
                    lng(m.get("issuedNs")),
                    m.get("retiredNs") == null ? null : lng(m.get("retiredNs")),
                    str(m, "issuedOnPathId")));
        }
        for (Object o : (List<Object>) p.getOrDefault("datagrams", List.of())) {
            Map<String, Object> m = (Map<String, Object>) o;
            st.datagrams.add(new Datagram(str(m, "id"), lng(m.get("tNs")),
                    Direction.valueOf(str(m, "dir")), str(m, "pathId"), str(m, "bytesHex")));
        }
        for (Object o : (List<Object>) p.getOrDefault("hpCandidates", List.of())) {
            Map<String, Object> m = (Map<String, Object>) o;
            st.hpCandidates.add(new HpCandidate(str(m, "id"), str(m, "packetId"),
                    str(m, "maskHex"), Boolean.TRUE.equals(m.get("applied")), str(m, "note")));
        }
        for (Object o : (List<Object>) p.getOrDefault("packets", List.of())) {
            st.packets.add(packetFromMap((Map<String, Object>) o));
        }
        processMaterials(st, e, largest, largestAcked, lastAckTimeNs, phase, currentGen,
                newKeySuccesses, lastFlipCommitNs, null);
    }

    @SuppressWarnings("unchecked")
    private static Packet packetFromMap(Map<String, Object> m) {
        Integer kpb = m.get("keyPhaseBit") == null ? null : intg(m.get("keyPhaseBit"));
        List<Long> gens = new ArrayList<>();
        for (Object g : (List<Object>) m.getOrDefault("decryptableGens", List.of())) {
            gens.add(lng(g));
        }
        return new Packet(str(m, "id"), str(m, "datagramId"), intg(m.get("offset")),
                PnSpace.valueOf(str(m, "space")), Boolean.TRUE.equals(m.get("longHeader")),
                lng(m.getOrDefault("version", 0L)), str(m, "dcidHex"), str(m, "scidHex"),
                lng(m.getOrDefault("keyGeneration", 0L)), kpb,
                lng(m.get("truncatedPn")), intg(m.get("pnLen")), List.copyOf(gens),
                m.get("ackFrameHex") == null ? null : str(m, "ackFrameHex"),
                str(m, "rawHeaderHex"));
    }

    @SuppressWarnings("unchecked")
    private static Decision decisionFromEvent(Event e) {
        Map<String, Object> m = payload(e);
        return new Decision(e.id(), Domain.DecisionType.valueOf(str(m, "type")),
                str(m, "targetId"), str(m, "chosenValue"), str(m, "rationale"),
                str(m, "author"), lng(m.get("atNs")), e.branch(), e.rootSeq());
    }

    /**
     * Source amendment: replaces one datagram (and its packets), invalidates every computation
     * whose parent chain touched the old material, then rebuilds. Deterministic computation ids
     * mean unchanged chains keep their identity; only the affected subtree changes.
     */
    @SuppressWarnings("unchecked")
    private static void applyAmend(
            ReplayState st, Event e,
            Map<PnSpace, Long> largest, Map<PnSpace, Long> largestAcked,
            Map<PnSpace, Long> lastAckTimeNs, Map<Direction, Integer> phase,
            Map<Direction, Long> currentGen, Map<Direction, Integer> newKeySuccesses,
            Map<Direction, Long> lastFlipCommitNs) {
        Map<String, Object> p = payload(e);
        String oldDg = str(p, "replacesDatagramId");
        Map<String, Object> dgMap = (Map<String, Object>) p.get("datagram");
        Datagram newDg = new Datagram(str(dgMap, "id"), lng(dgMap.get("tNs")),
                Direction.valueOf(str(dgMap, "dir")), str(dgMap, "pathId"), str(dgMap, "bytesHex"));

        List<String> invalidated = new ArrayList<>();
        for (Computation c : st.computations) {
            if (touches(c, oldDg)) {
                invalidated.add(c.id());
            }
        }
        List<Computation> invalidHold = new ArrayList<>();
        for (Computation c : st.computations) {
            if (invalidated.contains(c.id())) {
                invalidHold.add(new Computation(c.id(), c.kind(), c.inputDigest(), c.paramsVersion(),
                        c.parentIds(), c.resultJson(), e.seq(),
                        "source-amended by event " + e.id() + ": " + str(p, "note"),
                        c.atNs(), c.branch(), c.rootSeq()));
            }
        }

        st.datagrams.removeIf(d -> d.id().equals(oldDg));
        st.packets.removeIf(x -> x.datagramId().equals(oldDg));
        st.hpCandidates.removeIf(h -> {
            Packet pk = st.findPacketRaw(st, h.packetId());
            return pk != null && pk.datagramId().equals(oldDg);
        });
        st.datagrams.add(newDg);
        for (Object o : (List<Object>) p.getOrDefault("hpCandidates", List.of())) {
            Map<String, Object> m = (Map<String, Object>) o;
            st.hpCandidates.add(new HpCandidate(str(m, "id"), str(m, "packetId"),
                    str(m, "maskHex"), Boolean.TRUE.equals(m.get("applied")), str(m, "note")));
        }
        for (Object o : (List<Object>) p.getOrDefault("packets", List.of())) {
            st.packets.add(packetFromMap((Map<String, Object>) o));
        }

        for (PnSpace sp : PnSpace.values()) {
            largest.put(sp, -1L);
            largestAcked.put(sp, -1L);
            lastAckTimeNs.remove(sp);
        }
        phase.put(Direction.C2S, 0);
        phase.put(Direction.S2C, 0);
        currentGen.put(Direction.C2S, 0L);
        currentGen.put(Direction.S2C, 0L);
        newKeySuccesses.clear();
        lastFlipCommitNs.clear();

        st.findings.clear();
        st.computations.clear();
        processMaterials(st, e, largest, largestAcked, lastAckTimeNs, phase, currentGen,
                newKeySuccesses, lastFlipCommitNs, invalidHold);
    }

    private static Packet findPacketRaw(ReplayState st, String packetId) {
        for (Packet pk : st.packets) if (pk.id().equals(packetId)) return pk;
        return null;
    }

    private static boolean touches(Computation c, String oldDatagramId) {
        return c.parentIds().contains(oldDatagramId);
    }

    private static void processMaterials(
            ReplayState st, Event sourceEvent,
            Map<PnSpace, Long> largest, Map<PnSpace, Long> largestAcked,
            Map<PnSpace, Long> lastAckTimeNs, Map<Direction, Integer> phase,
            Map<Direction, Long> currentGen, Map<Direction, Integer> newKeySuccesses,
            Map<Direction, Long> lastFlipCommitNs,
            List<Computation> preInvalidated) {
        // Equivalent inputs must yield a stable order: (capture time, direction, id).
        List<Packet> ordered = new ArrayList<>(st.packets);
        ordered.sort((a, b) -> {
            Datagram da = st.datagram(a.datagramId());
            Datagram db = st.datagram(b.datagramId());
            int cmp = Long.compare(da.tNs(), db.tNs());
            if (cmp != 0) return cmp;
            cmp = da.dir().compareTo(db.dir());
            if (cmp != 0) return cmp;
            cmp = a.offset() - b.offset();
            if (cmp != 0) return cmp;
            return a.id().compareTo(b.id());
        });

        if (preInvalidated != null) st.computations.addAll(preInvalidated);

        for (Packet pk : ordered) {
            Datagram dg = st.datagram(pk.datagramId());
            if (dg == null) {
                st.diagnostics.add(Diagnostic.semantic("DATAGRAM_MISSING",
                        "packets/" + pk.id(),
                        "packet references missing datagram " + pk.datagramId()));
                continue;
            }
            if (st.budgetUsed + 3 > st.params.budgetUnits()) {
                st.outcome = Domain.Outcome.RESOURCE_EXHAUSTED;
                st.diagnostics.add(Diagnostic.budget("BUDGET_EXHAUSTED",
                        "packets/" + pk.id(),
                        "resource budget " + st.params.budgetUnits()
                                + " units exhausted at packet " + pk.id()
                                + " (used " + st.budgetUsed + ")"));
                break;
            }
            st.budgetUsed += 3;
            PacketFinding finding = new PacketFinding();

            // ---- packet number recovery in the packet's own number space ----
            long expected = Math.max(0L, largest.get(pk.space()) + 1);
            PnResult pn = recoverPacketNumber(expected, pk.truncatedPn(), pk.pnLenBytes());
            finding.pn = pn;
            if (pn.status() == PnStatus.UNSOLVABLE) {
                st.diagnostics.add(new Diagnostic("PN_UNSOLVABLE",
                        Domain.Outcome.SEMANTIC_UNSOLVABLE, "packets/" + pk.id() + "/truncatedPn",
                        null, pn.pnLen(), pn.note()));
            }
            finding.pnComputationId = recordComputation(st, sourceEvent, "pn_recovery", pk, dg,
                    pnMap(pn, expected), List.of());
            if (!pn.candidates().isEmpty()) {
                long chosen = pn.standard >= 0 ? pn.standard : pn.candidates().get(0);
                largest.put(pk.space(), Math.max(largest.get(pk.space()), chosen));
            }

            // ---- key phase / key update trajectory (1-RTT application space only) ----
            finding.keyPhase = evaluateKeyPhase(st, pk, dg, phase, currentGen,
                    newKeySuccesses, lastFlipCommitNs);
            finding.keyPhaseComputationId = recordComputation(st, sourceEvent, "key_phase", pk, dg,
                    keyPhaseMap(finding.keyPhase),
                    List.of(finding.pnComputationId));

            // ---- ACK frame ----
            if (pk.ackFrameHex() != null && !pk.ackFrameHex().isBlank()) {
                finding.ack = processAck(st, pk, dg, largestAcked, lastAckTimeNs);
                finding.ackComputationId = recordComputation(st, sourceEvent, "ack_frame", pk, dg,
                        ackMap(finding.ack), List.of(finding.pnComputationId));
            }
            finding.flags.addAll(finding.keyPhase == null ? List.of()
                    : List.of(finding.keyPhase.status));
            st.findings.put(pk.id(), finding);
        }
        applyDecisions(st);
    }

    private static KeyPhaseVerdict evaluateKeyPhase(
            ReplayState st, Packet pk, Datagram dg,
            Map<Direction, Integer> phase, Map<Direction, Long> currentGen,
            Map<Direction, Integer> newKeySuccesses, Map<Direction, Long> lastFlipCommitNs) {
        KeyPhaseVerdict v = new KeyPhaseVerdict();
        v.observedBit = pk.keyPhaseBit() == null ? 0 : pk.keyPhaseBit();
        v.phaseBefore = phase.get(dg.dir());
        v.phaseAfter = v.phaseBefore;
        long cur = currentGen.get(dg.dir());
        v.usedGen = cur;
        if (pk.space() != PnSpace.APPLICATION || pk.keyPhaseBit() == null) {
            v.status = "NOT_APPLICABLE";
            v.reason = "key phase bit exists only in 1-RTT short headers (RFC 9001 4.3)";
            return v;
        }
        boolean decryptNew = pk.decryptableGens().contains(cur + 1);
        boolean decryptCurrent = pk.decryptableGens().contains(cur);
        boolean decryptRetired = cur >= 1 && pk.decryptableGens().contains(cur - 1);
        Long commitNs = lastFlipCommitNs.get(dg.dir());

        if (v.observedBit != v.phaseBefore) {
            // Observed flip. Commit ONLY after the new generation decrypts successfully AND
            // keyUpdateConfirmCount consecutive new-key packets confirm it (RFC 9001 6.1).
            if (decryptNew) {
                int successes = newKeySuccesses.getOrDefault(dg.dir(), 0) + 1;
                newKeySuccesses.put(dg.dir(), successes);
                if (successes < st.params.keyUpdateConfirmCount()) {
                    v.status = "NEW_KEY_PENDING";
                    v.usedGen = cur + 1;
                    v.reason = "new key decrypts packet " + successes + "/"
                            + st.params.keyUpdateConfirmCount() + " required before commit";
                    return v;
                }
                v.status = "COMMITTED";
                v.phaseAfter = v.observedBit;
                v.usedGen = cur + 1;
                v.reason = "key phase committed after " + successes
                        + " consecutive packets decrypted with generation " + (cur + 1);
                phase.put(dg.dir(), v.observedBit);
                currentGen.put(dg.dir(), cur + 1);
                lastFlipCommitNs.put(dg.dir(), dg.tNs());
                newKeySuccesses.put(dg.dir(), 0);
                return v;
            }
            if (decryptRetired) {
                long dt = commitNs == null ? Long.MAX_VALUE : dg.tNs() - commitNs;
                v.usedGen = cur - 1;
                if (commitNs != null && dt <= st.params.oldKeyGraceNs()) {
                    v.status = "GRACE_OLD_KEY";
                    v.reason = "phase bit disagrees but packet decrypts with retired generation "
                            + (cur - 1) + " within " + st.params.oldKeyGraceNs()
                            + " ns grace; accepted, phase not rolled back";
                    return v;
                }
                v.status = "OLD_KEY_EXPIRED";
                v.reason = "only retired generation " + (cur - 1) + " decrypts, " + dt
                        + " ns after update (grace " + st.params.oldKeyGraceNs() + " ns)";
                st.diagnostics.add(new Domain.Diagnostic("OLD_KEY_EXPIRED",
                        Domain.Outcome.SEMANTIC_UNSOLVABLE,
                        "packets/" + pk.id() + "/keyGeneration", null, null, v.reason));
                return v;
            }
            v.status = "MISFLIP_REJECTED";
            v.reason = "key phase bit flipped to " + v.observedBit
                    + " but no new generation decrypts the packet; flip not committed";
            st.diagnostics.add(new Domain.Diagnostic("KEY_PHASE_MISFLIP",
                    Domain.Outcome.SEMANTIC_UNSOLVABLE,
                    "packets/" + pk.id() + "/keyPhaseBit", null, 1, v.reason));
            newKeySuccesses.put(dg.dir(), 0);
            return v;
        }

        if (decryptCurrent) {
            v.status = "OK";
            v.reason = "key phase bit consistent; decrypted with generation " + cur;
            newKeySuccesses.put(dg.dir(), 0);
            return v;
        }
        if (decryptRetired) {
            long dt = commitNs == null ? Long.MAX_VALUE : dg.tNs() - commitNs;
            v.usedGen = cur - 1;
            if (commitNs != null && dt <= st.params.oldKeyGraceNs()) {
                v.status = "GRACE_OLD_KEY";
                v.reason = "late packet on retired generation " + (cur - 1) + " within "
                        + st.params.oldKeyGraceNs() + " ns grace; phase not rolled back";
                return v;
            }
            v.status = "OLD_KEY_EXPIRED";
            v.reason = "retired generation " + (cur - 1) + " used " + dt + " ns after update"
                    + " (grace " + st.params.oldKeyGraceNs() + " ns)";
            st.diagnostics.add(new Domain.Diagnostic("OLD_KEY_EXPIRED",
                    Domain.Outcome.SEMANTIC_UNSOLVABLE,
                    "packets/" + pk.id() + "/keyGeneration", null, null, v.reason));
            return v;
        }
        v.status = "HOLE";
        v.reason = "packet not decryptable with any available generation "
                + pk.decryptableGens() + "; recorded as undecryptable hole";
        st.diagnostics.add(new Domain.Diagnostic("UNDECRYPTABLE_HOLE",
                Domain.Outcome.SEMANTIC_UNSOLVABLE,
                "packets/" + pk.id() + "/decryptableGens", null, null, v.reason));
        return v;
    }

    private static AckFinding processAck(ReplayState st, Packet pk, Datagram dg,
                                         Map<PnSpace, Long> largestAcked,
                                         Map<PnSpace, Long> lastAckTimeNs) {
        AckFinding f = new AckFinding();
        byte[] frame;
        try {
            frame = hex(pk.ackFrameHex());
        } catch (IllegalArgumentException bad) {
            st.diagnostics.add(Diagnostic.format("ACK_HEX_INVALID",
                    "packets/" + pk.id() + "/ackFrameHex", 0, bad.getMessage()));
            f.flags.add("FORMAT_CORRUPT");
            return f;
        }
        AckRead read = parseAckFrame(frame, "packets/" + pk.id() + "/ackFrameHex");
        f.largest = read.largest;
        f.ackDelayNs = read.ackDelayNs;
        f.ranges = read.ranges;
        if (!read.errors.isEmpty()) {
            st.diagnostics.addAll(read.errors);
            boolean semantic = read.errors.stream()
                    .anyMatch(d -> d.kind() == Domain.Outcome.SEMANTIC_UNSOLVABLE);
            f.flags.add(semantic ? "SEMANTIC_UNSOLVABLE" : "FORMAT_CORRUPT");
            return f;
        }
        long prevLargest = largestAcked.getOrDefault(pk.space(), -1L);
        long prevTime = lastAckTimeNs.getOrDefault(pk.space(), Long.MIN_VALUE);
        if (read.largest < prevLargest) {
            boolean withinTolerance = dg.tNs() - prevTime <= st.params.ackReorderToleranceNs();
            f.flags.add(withinTolerance ? "OUT_OF_ORDER_WITHIN_TOLERANCE" : "OUT_OF_ORDER");
            st.diagnostics.add(new Diagnostic("ACK_REORDERED",
                    withinTolerance ? Domain.Outcome.OK : Domain.Outcome.SEMANTIC_UNSOLVABLE,
                    "packets/" + pk.id() + "/ackFrameHex", null, null,
                    "ACK largest " + read.largest + " arrived after " + prevLargest + ", "
                            + (dg.tNs() - prevTime) + " ns after prior ACK (tolerance "
                            + st.params.ackReorderToleranceNs() + " ns"
                            + (withinTolerance ? ", within tolerance)" : ", beyond tolerance)")));
        }
        if (read.ranges.size() > 1) f.flags.add("GAP_RANGES");
        largestAcked.put(pk.space(), Math.max(prevLargest, read.largest));
        lastAckTimeNs.put(pk.space(), dg.tNs());
        return f;
    }

    // ---------------------------------------------------- provenance/audit

    private static String recordComputation(ReplayState st, Event sourceEvent, String kind,
                                            Packet pk, Datagram dg,
                                            Map<String, Object> result, List<String> extraParents) {
        Map<String, Object> input = new LinkedHashMap<>(result);
        input.put("packetId", pk.id());
        input.put("paramsLabel", st.params.revisionLabel());
        String canonical = Json.canonical(input);
        String digest = Ids.sha1Hex(canonical);
        String id = Ids.of("cp-" + kind + "-", canonical);
        List<String> parents = new ArrayList<>();
        parents.add(sourceEvent.id());
        parents.add(dg.id());
        parents.add(pk.id());
        parents.addAll(extraParents);
        Computation c = new Computation(id, kind, digest, st.paramsVersion, List.copyOf(parents),
                Json.write(result), null, null, dg.tNs(), sourceEvent.branch(), sourceEvent.rootSeq());
        st.computations.add(c);
        return id;
    }

    private static Map<String, Object> pnMap(PnResult pn, long expected) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("expectedPn", expected);
        m.put("truncatedPn", pn.truncated());
        m.put("pnLenBytes", pn.pnLen());
        m.put("windowSize", pn.window());
        m.put("windowUnit", "packet numbers (2^(8*pnLenBytes))");
        m.put("standardCandidate", pn.standard());
        m.put("candidates", pn.candidates());
        m.put("status", pn.status().name());
        m.put("note", pn.note());
        return m;
    }

    private static Map<String, Object> keyPhaseMap(KeyPhaseVerdict v) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("status", v.status);
        m.put("observedBit", v.observedBit);
        m.put("phaseBefore", v.phaseBefore);
        m.put("phaseAfter", v.phaseAfter);
        m.put("usedGeneration", v.usedGen);
        m.put("reason", v.reason);
        return m;
    }

    private static Map<String, Object> ackMap(AckFinding f) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("largestAcked", f.largest);
        m.put("ackDelayUnit", "ns (raw ACK Delay field, not yet ECN-scaled)");
        m.put("ackDelay", f.ackDelayNs);
        List<Map<String, Object>> ranges = new ArrayList<>();
        for (AckRange r : f.ranges) {
            Map<String, Object> rm = new LinkedHashMap<>();
            rm.put("first", r.first());
            rm.put("last", r.last());
            rm.put("unit", "packet numbers within this packet-number space");
            ranges.add(rm);
        }
        m.put("ranges", ranges);
        m.put("flags", f.flags);
        return m;
    }

    /** Applies reviewer decisions to the visible pn findings (ambiguous windows). */
    private static void applyDecisions(ReplayState st) {
        for (Decision d : st.decisions) {
            if (d.type() != Domain.DecisionType.ACCEPT_CANDIDATE
                    && d.type() != Domain.DecisionType.REJECT_CANDIDATE) {
                continue;
            }
            // targetId is the pn_recovery computation; resolve owning packet through parents.
            Packet target = null;
            for (Computation c : st.computations) {
                if (c.id().equals(d.targetId()) && c.kind().equals("pn_recovery")) {
                    for (String pid : c.parentIds()) {
                        Packet pk = st.packet(pid);
                        if (pk != null) { target = pk; break; }
                    }
                }
            }
            }
        }
    }

    /** Best committed pn for a packet after reviewer decisions; absent when still ambiguous. */
    public static Optional<Long> committedPn(ReplayState st, Packet pk) {
        PacketFinding f = st.findings.get(pk.id());
        if (f == null || f.pn == null) return Optional.empty();
        String cid = f.pnComputationId;
        List<Long> accepted = new ArrayList<>();
        for (Decision d : st.decisions) {
            if (d.targetId().equals(cid) && d.type() == Domain.DecisionType.ACCEPT_CANDIDATE) {
                try { accepted.add(Long.parseLong(d.chosenValue())); }
                catch (NumberFormatException ignored) { }
            }
        }
        if (accepted.size() == 1) return Optional.of(accepted.get(0));
        if (f.pn.status() == PnStatus.AMBIGUOUS) return Optional.empty();
        return f.pn.standard() >= 0 ? Optional.of(f.pn.standard()) : Optional.empty();
    }
}
