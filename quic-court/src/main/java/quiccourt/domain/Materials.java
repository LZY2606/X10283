package quiccourt.domain;

/**
 * 不可变材料层：传输协议团队导入的原始证据。
 *
 * 分层原则：原数据报字节、截断 packet number、header protection 候选、密钥代次、
 * CID 事件、path 与 ACK range 均保留原始表示（*Raw 字段）；规范化后的派生值
 * 可空，无法转换时为 null 并附诊断，绝不为了画图而丢弃原值。
 */
public final class Materials {

    private Materials() {
    }

    public enum Direction {
        RX, TX
    }

    public enum PnSpace {
        INITIAL("Initial"), HANDSHAKE("Handshake"), APPLICATION("Application");

        public final String label;

        PnSpace(String label) {
            this.label = label;
        }

        public static PnSpace fromRaw(String raw) {
            for (PnSpace s : values()) {
                if (s.name().equalsIgnoreCase(raw) || s.label.equalsIgnoreCase(raw)) {
                    return s;
                }
            }
            throw new IllegalArgumentException("unknown packet number space: " + raw);
        }
    }

    /** 所有材料共享的不可变信封。 */
    public record Material(
            String id,
            String kind,
            int batchSeq,
            String batchId,
            String supersedesId,
            String rawJson
    ) {
    }

    /**
     * 原数据报字节 + 截断 packet number + 头部字段。
     * timeRaw 与 tMicros、truncatedPnRaw 与 truncatedPn 是“原始表示 / 派生规范化”两层。
     */
    public record Datagram(
            Material envelope,
            String timeRaw,
            Long tMicros,
            Direction direction,
            String pathId,
            String bytesHex,
            int byteLength,
            int firstByte,
            PnSpace space,
            String truncatedPnRaw,
            Long truncatedPn,
            Integer pnLengthBytesRaw,
            int pnLengthBytes,
            String hpCandidateId,
            String keyEpochId,
            String decryptCandidateId,
            String dcidRef,
            String scidRef,
            String ackRangeId,
            String keyPhaseBitRaw,
            Boolean keyPhaseBit,
            String decryptStatusRaw,
            String scenarioTag
    ) {
        public String id() {
            return envelope.id();
        }
    }

    /** header protection 候选：掩码、样本位置、PN 长度均保留原始表示。 */
    public record HeaderProtectionCandidate(
            Material envelope,
            String label,
            String sampleOffsetRaw,
            Long sampleOffsetBytes,
            String pnLengthRaw,
            Integer pnLengthBytes,
            String maskHex,
            String statusRaw
    ) {
        public String id() {
            return envelope.id();
        }
    }

    /** 密钥代次与谱系：parentEpochId 描述密钥链，graceWindowMicrosRaw 为旧密钥宽限原始值。 */
    public record KeyEpoch(
            Material envelope,
            String label,
            int ordinal,
            String phaseBitRaw,
            Boolean phaseBit,
            String secretRef,
            String parentEpochId,
            String graceWindowMicrosRaw,
            Long graceWindowMicros
    ) {
        public String id() {
            return envelope.id();
        }
    }

    /** CID 事件：新增/退役/绑定/使用；构成 CID 谱系。 */
    public record CidEvent(
            Material envelope,
            String timeRaw,
            Long tMicros,
            String eventTypeRaw,
            String cidHex,
            String sequenceNumberRaw,
            Long sequenceNumber,
            String boundPathId,
            String replacesCidHex
    ) {
        public String id() {
            return envelope.id();
        }
    }

    /** path 证据：保留原始五元组文本；migrationFromPathId 表达路径迁移关系。 */
    public record PathRecord(
            Material envelope,
            String label,
            String localTupleRaw,
            String remoteTupleRaw,
            String firstSeenRaw,
            Long firstSeenMicros,
            String migrationFromPathId
    ) {
        public String id() {
            return envelope.id();
        }
    }

    /** ACK range：largest/first-range/gap 块全部保留原始表示，派生层才规范化为区间。 */
    public record AckRange(
            Material envelope,
            String timeRaw,
            Long tMicros,
            PnSpace space,
            Direction direction,
            String largestRaw,
            Long largest,
            String smallestRaw,
            Long smallest,
            String gapBlocksRaw,
            String rawRepresentation
    ) {
        public String id() {
            return envelope.id();
        }
    }

    /** 解密候选：记录解密判定与原因（成功/旧密钥宽限/无法解密空洞）。 */
    public record DecryptCandidate(
            Material envelope,
            String label,
            String datagramId,
            String epochId,
            String keyPhaseExpectedRaw,
            Boolean keyPhaseExpected,
            String verdictRaw,
            String reasonRaw
    ) {
        public String id() {
            return envelope.id();
        }

        public boolean adopted() {
            return verdictRaw != null && verdictRaw.trim().equalsIgnoreCase("SUCCESS");
        }
    }
}
