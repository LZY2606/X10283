package org.quiccourt.domain;

import java.util.List;

/**
 * Immutable source material layer. These records are imported verbatim and never
 * rewritten by computation. Every raw numeric/quantitative field keeps its
 * original representation plus unit/coordinate basis; normalization happens only
 * in the derived layer.
 */
public final class Material {

    /** A raw datagram as captured on a path. */
    public static final class Datagram {
        public final String id;
        public final Quant time;
        public final Direction direction;
        public final String pathId;
        public final String rawHex;
        public final String timeBasis;

        public Datagram(String id, Quant time, Direction direction, String pathId,
                        String rawHex, String timeBasis) {
            this.id = id;
            this.time = time;
            this.direction = direction;
            this.pathId = pathId;
            this.rawHex = rawHex;
            this.timeBasis = timeBasis;
        }
    }

    /** Parsed-but-immutable QUIC header claim, attached to a datagram. */
    public static final class Header {
        public final String id;
        public final String datagramId;
        public final String packetType;
        public final PnSpace space;
        public final String truncatedPnHex;
        public final Integer pnBytes;
        public final String headerProtectionCandidateId;
        public final Integer keyPhaseBit;
        public final String scidRaw;
        public final String dcidRaw;
        public final List<String> decryptionCandidateIds;
        public final boolean decryptable;

        public Header(String id, String datagramId, String packetType, PnSpace space,
                      String truncatedPnHex, Integer pnBytes, String headerProtectionCandidateId,
                      Integer keyPhaseBit, String scidRaw, String dcidRaw,
                      List<String> decryptionCandidateIds, boolean decryptable) {
            this.id = id;
            this.datagramId = datagramId;
            this.packetType = packetType;
            this.space = space;
            this.truncatedPnHex = truncatedPnHex;
            this.pnBytes = pnBytes;
            this.headerProtectionCandidateId = headerProtectionCandidateId;
            this.keyPhaseBit = keyPhaseBit;
            this.scidRaw = scidRaw;
            this.dcidRaw = dcidRaw;
            this.decryptionCandidateIds = decryptionCandidateIds;
            this.decryptable = decryptable;
        }
    }

    /** A header-protection mask candidate (one of possibly several). */
    public static final class HpCandidate {
        public final String id;
        public final String label;
        public final String sampleHex;
        public final String maskHex;

        public HpCandidate(String id, String label, String sampleHex, String maskHex) {
            this.id = id;
            this.label = label;
            this.sampleHex = sampleHex;
            this.maskHex = maskHex;
        }
    }

    /** A decryption attempt result against one key generation. */
    public static final class DecryptionCandidate {
        public final String id;
        public final int keyGeneration;
        public final PnSpace space;
        public final boolean success;
        public final String note;

        public DecryptionCandidate(String id, int keyGeneration, PnSpace space,
                                   boolean success, String note) {
            this.id = id;
            this.keyGeneration = keyGeneration;
            this.space = space;
            this.success = success;
            this.note = note;
        }
    }

    /** A connection ID lineage event as observed. */
    public static final class CidEvent {
        public final String id;
        public final String cid;
        public final String role;        // ISSUE, USE, RETIRE
        public final String boundPathId;
        public final Quant time;
        public final String datagramId;  // nullable
        public final Integer retirePriorTo;

        public CidEvent(String id, String cid, String role, String boundPathId, Quant time,
                        String datagramId, Integer retirePriorTo) {
            this.id = id;
            this.cid = cid;
            this.role = role;
            this.boundPathId = boundPathId;
            this.time = time;
            this.datagramId = datagramId;
            this.retirePriorTo = retirePriorTo;
        }
    }

    /** A network path as identified by local+remote address/port tuple. */
    public static final class PathInfo {
        public final String id;
        public final String localAddr;
        public final String localPort;
        public final String remoteAddr;
        public final String remotePort;
        public final Quant firstSeen;

        public PathInfo(String id, String localAddr, String localPort, String remoteAddr,
                        String remotePort, Quant firstSeen) {
            this.id = id;
            this.localAddr = localAddr;
            this.localPort = localPort;
            this.remoteAddr = remoteAddr;
            this.remotePort = remotePort;
            this.firstSeen = firstSeen;
        }

        public String fiveTupleLabel() {
            return localAddr + ":" + localPort + "->" + remoteAddr + ":" + remotePort;
        }
    }

    /** A raw ACK range block belonging to one packet (largest-first encoding). */
    public static final class AckRange {
        public final String id;
        public final String headerId;
        public final String largestRaw;
        public final String gapRaw;
        public final String ackRangeRaw;
        public final String firstRangeRaw;
        public final String ackDelayRaw;
        public final String ackDelayUnit;

        public AckRange(String id, String headerId, String largestRaw, String gapRaw,
                        String ackRangeRaw, String firstRangeRaw, String ackDelayRaw,
                        String ackDelayUnit) {
            this.id = id;
            this.headerId = headerId;
            this.largestRaw = largestRaw;
            this.gapRaw = gapRaw;
            this.ackRangeRaw = ackRangeRaw;
            this.firstRangeRaw = firstRangeRaw;
            this.ackDelayRaw = ackDelayRaw;
            this.ackDelayUnit = ackDelayUnit;
        }
    }

    private Material() {
    }
}
