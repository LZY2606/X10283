package quiccourt.domain;

import java.util.List;

/** Derived (normalized) view. Raw materials stay untouched; all values here carry
 *  explicit units or coordinate bases in field names and legends. */
public record View(
        List<PacketRow> packets,
        List<KpCandidate> keyPhaseCandidates,
        List<Generation> generations,
        List<AckFrame> ackFrames,
        List<long[]> ackRangesBySpace,   // flattened [spaceOrd, lo, hi]
        List<CidNode> cidNodes,
        List<PathSeg> pathSegments,
        List<Migration> migrations,
        List<Diag> diags) {

    public static final String[] SPACES = {"initial", "handshake", "application"};

    public static int spaceOrd(String space) {
        for (int i = 0; i < SPACES.length; i++) if (SPACES[i].equals(space)) return i;
        return -1;
    }

    /** One packet row. tNs uses coordinate base "ns since connection start (monotonic)".
     *  pn is dimensionless inside its packet number space. */
    public record PacketRow(
            String datagramId, String headerId, String space,
            Long tNs, String timeRaw, String direction, String pathId, String tuple5,
            Long truncatedPn, Integer pnBits, Integer keyPhaseBit,
            Integer keyGen, String decryptStatus,
            Long pn, List<Long> pnCandidates, String pnStatus,
            List<Diag> diags) {}

    /** A key phase flip candidate: committed only after successful decrypt with the new
     *  generation AND a confirmation packet; otherwise rejected with a reason. */
    public record KpCandidate(String id, long firstSeenNs, int fromGen, int toGen,
                              String status, String reason, List<String> evidence) {}

    /** A committed key generation with its validity interval and invalidation reason. */
    public record Generation(int gen, Long validFromNs, Long validToNs, String invalidationReason) {}

    public record AckFrame(String id, String space, Long tNs, long ackDelayUs,
                           List<long[]> ranges, List<long[]> newlyAcked) {}

    public record CidNode(String id, int seq, String cidHex, String state,
                          Long tNs, String pathId) {}

    public record PathSeg(String pathId, String tuple5, Long firstSeenNs, Long lastSeenNs,
                          String invalidationReason) {}

    public record Migration(String id, String fromPath, String toPath, long tNs,
                            int cidSeq, boolean connectionContinues, String basis) {}
}
