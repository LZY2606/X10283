package quiccourt.model;

import java.util.List;

/**
 * Immutable evidence items. Raw representations (hex bytes, original number strings,
 * unit/basis annotations) are preserved verbatim; normalization happens only in the
 * derived layer. Unconvertible values stay in place and produce diagnostics.
 */
public sealed interface Evidence {
    String id();
    String kind();
    long seq();

    /** A captured datagram: raw bytes + arrival metadata. */
    record Datagram(String id, long seq, String rawBytesHex, String timeRaw, Long timeUs,
                    String timeBasis, String direction, String pathId) implements Evidence {
        public String kind() { return "datagram"; }
    }

    /** A decoded packet header observation derived from a datagram. */
    record PacketObs(String id, long seq, String datagramId, String pnSpace,
                     String truncatedPnRaw, Long truncatedPn, int pnLengthBytes,
                     Integer keyPhaseBit, long keyGeneration,
                     List<String> hpCandidatesHex, String dcidHex, String scidHex,
                     String decryptStatus, String payloadKind) implements Evidence {
        public String kind() { return "packet"; }
    }

    /** Connection ID lifecycle event. */
    record CidEvent(String id, long seq, String eventKind, String cidHex, long cidSequence,
                    String pathId, Long timeUs) implements Evidence {
        public String kind() { return "cid-event"; }
    }

    /** ACK ranges as received, per packet number space. */
    record AckRanges(String id, long seq, String pnSpace, List<long[]> ranges,
                     long largestAcked, Long ackDelayUs, String direction) implements Evidence {
        public String kind() { return "ack-ranges"; }
    }

    /** Path / migration event. Five-tuple change never severs the connection by itself. */
    record PathEvent(String id, long seq, String pathId, String eventKind,
                     String srcAddr, int srcPort, String dstAddr, int dstPort,
                     Long timeUs) implements Evidence {
        public String kind() { return "path-event"; }
    }
}
