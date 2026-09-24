package quictribunal.model;

import java.util.List;

/**
 * Immutable domain types for the QUIC packet tribunal.
 *
 * <p>Two layers live in distinct places:
 * <ul>
 *   <li><b>materials</b> ({@link Datagram}, {@link Packet}, {@link HpCandidate},
 *       {@link KeyGen}, {@link CidEvent}, {@link PathInfo}) are imported once and never mutated;
 *       a source change introduces a new material with a new stable id and an
 *       explicit amend event.</li>
 *   <li><b>decisions / derived results</b> ({@link Decision}, computations) are versioned and
 *       carry input digest, rule-parameter version and parent dependencies.</li>
 * </ul>
 */
public final class Domain {
    private Domain() {}

    public enum PnSpace { INITIAL, HANDSHAKE, APPLICATION }

    public enum Direction { C2S, S2C }

    public enum KeyRole { INITIAL, HANDSHAKE, APP_0RTT, APP_1RTT }

    /** The three failure classes must never collapse into a single generic error. */
    public enum Outcome { OK, RESOURCE_EXHAUSTED, FORMAT_CORRUPT, SEMANTIC_UNSOLVABLE }

    public enum EventType {
        PROJECT_CREATED,
        MATERIALS_IMPORTED,
        IMPORT_REJECTED,
        PARAMS_REVISED,
        SOURCE_AMENDED,
        DECISION_RECORDED,
        BRANCH_CREATED
    }

    public enum DecisionType {
        ACCEPT_CANDIDATE,
        REJECT_CANDIDATE,
        ADJUST_PARAM
    }

    /** Rule parameters that reviewers are allowed to revise. */
    public record RuleParams(
            long oldKeyGraceNs,
            int keyUpdateConfirmCount,
            long ackReorderToleranceNs,
            long budgetUnits,
            String revisionLabel) {
        public static RuleParams v1() {
            // grace 2 ms; two consecutive new-key packets confirm a key update (RFC 9001 6.1);
            // 5 ms reorder tolerance; 4000 engine work units budget.
            return new RuleParams(2_000_000L, 2, 5_000_000L, 4_000L, "v1");
        }
    }

    /** A position-bearing diagnostic. {@code path} uses JSON pointer-ish positions into the import. */
    public record Diagnostic(
            String code,
            Outcome kind,
            String path,
            Integer offset,
            Integer length,
            String message) {
        public java.util.Map<String, Object> toMap() {
            java.util.LinkedHashMap<String, Object> m = new java.util.LinkedHashMap<>();
            m.put("code", code);
            m.put("kind", kind.name());
            m.put("path", path);
            m.put("offset", offset);
            m.put("length", length);
            m.put("message", message);
            return m;
        }

        public static Diagnostic format(String code, String path, Integer offset, String message) {
            return new Diagnostic(code, Outcome.FORMAT_CORRUPT, path, offset, null, message);
        }

        public static Diagnostic semantic(String code, String path, String message) {
            return new Diagnostic(code, Outcome.SEMANTIC_UNSOLVABLE, path, null, null, message);
        }

        public static Diagnostic budget(String code, String path, String message) {
            return new Diagnostic(code, Outcome.RESOURCE_EXHAUSTED, path, null, null, message);
        }
    }

    /** Raw datagram exactly as captured. {@code bytesHex} is the original representation. */
    public record Datagram(String id, long tNs, Direction dir, String pathId, String bytesHex) {}

    /** One header-protection candidate mask, kept whether or not it was adopted. */
    public record HpCandidate(String id, String packetId, String maskHex, boolean applied, String note) {}

    /**
     * Parsed-but-uninterpreted QUIC packet header. The truncated packet number and key phase bit
     * are raw observations; recovery/key-update interpretation belongs to the engine.
     */
    public record Packet(
            String id,
            String datagramId,
            int offset,
            PnSpace space,
            boolean longHeader,
            long version,
            String dcidHex,
            String scidHex,
            long keyGeneration,
            Integer keyPhaseBit,
            long truncatedPn,
            int pnLenBytes,
            List<Long> decryptableGens,
            String ackFrameHex,
            String rawHeaderHex) {}

    /** A key generation in the secret schedule, including validity time window. */
    public record KeyGen(
            String id, KeyRole role, long generation,
            long validFromNs, Long validUntilNs, String secretLabel) {}

    /** Connection-ID issuance/retirement event forming the CID genealogy. */
    public record CidEvent(
            String id, long seq, String cidHex,
            long issuedNs, Long retiredNs, String issuedOnPathId) {}

    public record PathInfo(String id, String fourTuple) {}

    public record AckRange(long first, long last) {}

    /** One event in the append-only event log. */
    public record Event(
            long seq,
            String id,
            EventType type,
            String branch,
            Long rootSeq,
            long atNs,
            String parentId,
            String payloadJson) {}

    /** A human decision; conflicts are retained across branches, never overwritten. */
    public record Decision(
            String id,
            DecisionType type,
            String targetId,
            String chosenValue,
            String rationale,
            String author,
            long atNs,
            String branch,
            Long rootSeq) {}

    /**
     * A derived result with full provenance. {@code invalidReason} is non-null once a later
     * amend/decision invalidates this computation; historical replays still surface it.
     */
    public record Computation(
            String id,
            String kind,
            String inputDigest,
            int paramsVersion,
            List<String> parentIds,
            String resultJson,
            Long invalidatedAtSeq,
            String invalidReason,
            long atNs,
            String branch,
            Long rootSeq) {}
}
