package org.quiccourt.model;

import java.util.List;
import java.util.Map;

/**
 * 核心领域模型。
 *
 * 分层约定：
 * - 不可变材料层（Materials）：原数据报字节、截断 packet number、header protection 候选、
 *   密钥代次、CID 事件、path、ACK range，导入时只做保真记录与校验，不做静默规范化。
 * - 决定层（Decisions）：人工接受/否定/参数修订，带父级依赖与参数版本。
 * - 派生层（Derived）：恢复窗口候选、key phase 状态、CID 解析等，全部可重放。
 */
public final class Models {
    private Models() {}

    public static final String RULES_VERSION = "qc-rules-1.0.0";
    public static final int MAX_PACKET_NUMBER = (1 << 62) - 1;

    public enum Direction { RX, TX }
    public enum Space { INITIAL, HANDSHAKE, APPLICATION }

    public enum OutcomeKind {
        OK,
        /** 资源预算耗尽（例如候选数量超过上限）。 */
        BUDGET_EXHAUSTED,
        /** 输入格式损坏（字节非法、JSON 字段缺失/类型错）。 */
        MALFORMED,
        /** 语义无解（无合法 packet number、key phase 矛盾无法提交等）。 */
        SEMANTICALLY_UNRESOLVABLE
    }

    /** 带位置的诊断，position 指向导入片段/字段路径，如 datagrams[3].truncatedPn。 */
    public record Diagnostic(String code, String position, String message, String rawValue) {
        public Map<String, Object> toMap() {
            return Map.of("code", code, "position", position, "message", message,
                    "rawValue", rawValue == null ? "" : rawValue);
        }
    }

    /** 带坐标基准的时间：原始表示保留在 rawText，规范化值为微秒。 */
    public record TimestampRef(String rawText, long epochUs, String basis) {
        public Map<String, Object> toMap() {
            return Map.of("raw", rawText, "epochUs", epochUs, "basis", basis);
        }
    }

    /** 四/五元组层面的 path（迁移判定不据此切断连接）。 */
    public record PathRef(String id, String localAddr, int localPort,
                          String remoteAddr, int remotePort, String note) {}

    /** header protection 候选：hpMask 用十六进制保留原始观测。 */
    public record HpCandidate(String keyLabel, String hpMaskHex, int confidence, String note) {}

    /** 密钥代次观测/候选。 */
    public record KeyGenerationRef(long generation, String secretLabel,
                                   Integer phaseBit, String source) {}

    /** ACK range：RFC 9000 区间语义，ackOnly=true 表示该区间来自 ACK 帧而非直接观测包。 */
    public record AckRange(long largest, long smallest, boolean ackOnly, String evidenceId) {}

    /** 一个 ACK 帧观测（挂在携带 ACK 的包上）。 */
    public record AckFrame(String id, long ackDelayUs, long firstAckRange,
                           List<Long> gapBlocks, List<Long> ackRangeBlocks, List<AckRange> ranges) {}

    /** CID 事件，谱系材料。 */
    public record CidEvent(String id, String type, String timeRaw,
                           String cidHex, Long sequence, String retirePriorTo,
                           String pathId, String note) {}

    /** 解密候选材料。 */
    public record DecryptCandidate(String keyLabel, long keyGeneration,
                                   String result, String detail) {}

    /**
     * 不可变数据报材料。truncatedPn 保留原始十六进制表示；pnBits 为截断长度（8/16/24/32）。
     */
    public record DatagramMaterial(
            String id,
            String timeRaw,
            Direction direction,
            Space space,
            String pathId,
            String rawHex,
            long truncatedPn,
            int pnBits,
            String dcidHex,
            String scidHex,
            Boolean keyPhaseBit,
            List<HpCandidate> hpCandidates,
            List<KeyGenerationRef> keyGenerations,
            List<DecryptCandidate> decryptCandidates,
            AckFrame ackFrame,
            String note) {}

    public record ParameterSet(
            int windowPnBits,
            long maxCandidates,
            int oldKeyGracePackets,
            String rulesVersion,
            String note) {}

    /** 恢复出的 packet number 候选（派生层）。 */
    public record PnCandidate(long packetNumber, boolean rfc9000Canonical,
                              boolean selected, String rejectReason) {}

    /** 单包 packet number 恢复结果。 */
    public record PnRecoveryResult(
            String datagramId, Space space, Direction direction,
            long truncatedPn, int pnBits, long expectedPn,
            List<PnCandidate> candidates,
            OutcomeKind outcome, List<Diagnostic> diagnostics,
            String inputSummary, String paramsVersion, List<String> parentIds) {}

    public record AckStateView(
            Direction direction, Space space,
            List<AckRange> mergedRanges,
            List<long[]> holes,
            List<UndecryptableHole> undecryptableHoles,
            List<Diagnostic> diagnostics,
            String inputSummary, String paramsVersion, List<String> parentIds) {}

    public record UndecryptableHole(long afterPn, long beforePn, String reason, String evidenceId) {}

    public enum KpState { NO_1RTT, UNCONFIRMED, NORMAL, FLIP_PENDING, FLIPPED, CONTRADICTION }

    public record KpStep(
            String datagramId, long packetNumber, Boolean observedBit,
            Boolean decryptOk, String keyLabel, long generation,
            KpState from, KpState to, String rule,
            boolean committed, String reason, long graceRemaining) {}

    public record KeyPhaseTrack(
            Direction direction, KpState state, long currentGeneration,
            List<KpStep> steps,
            List<Diagnostic> diagnostics,
            String inputSummary, String paramsVersion, List<String> parentIds) {}

    public record CidLineage(
            List<CidNode> nodes, List<CidEdge> edges, String activeDcidHex,
            List<Diagnostic> diagnostics,
            String inputSummary, String paramsVersion, List<String> parentIds) {}

    public record CidNode(String cidHex, Long sequence, String firstSeenId,
                          String status, String retiredByEventId) {}

    public record CidEdge(String fromCidHex, String toCidHex, String eventId, String kind) {}

    public record PathSegment(String pathId, long enterEpochUs, Long exitEpochUs,
                              String enterDatagramId, String kind, String reason) {}

    public record MigrationView(
            String connectionKey, List<PathSegment> segments,
            List<MigrationEvent> events,
            List<Diagnostic> diagnostics,
            String inputSummary, String paramsVersion, List<String> parentIds) {}

    public record MigrationEvent(String datagramId, String pathId, String kind,
                                 String reason, Boolean connectionCut) {}
}
