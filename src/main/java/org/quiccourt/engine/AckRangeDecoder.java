package org.quiccourt.engine;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import org.quiccourt.domain.Material;

/**
 * Decodes ACK Range blocks (RFC 9000 §19.3) and classifies arrival ordering.
 *
 * <p>Range reconstruction is pure arithmetic over the largest-first wire
 * encoding. Malformed encodings producing negative starts are FORMAT_CORRUPT;
 * overlapping blocks are SEMANTIC_NO_SOLUTION. Ranges spanning undecryptable
 * packet-number holes are UNVERIFIABLE rather than silently confirmed.
 */
public final class AckRangeDecoder {

    public static final class Block {
        public final long start;
        public final long end;

        Block(long start, long end) {
            this.start = start;
            this.end = end;
        }
    }

    public static final class Decoded {
        public final List<Block> blocks;
        public final ResultStatus status;
        public final String note;

        Decoded(List<Block> blocks, ResultStatus status, String note) {
            this.blocks = blocks;
            this.status = status;
            this.note = note;
        }
    }

    private AckRangeDecoder() {
    }

    /** Decode one range block list (in wire order: block 0 uses firstRange). */
    public static Decoded decode(List<Material.AckRange> wire, long prevLargest) {
        List<Block> blocks = new ArrayList<>();
        for (int i = 0; i < wire.size(); i++) {
            Material.AckRange r = wire.get(i);
            long largest;
            long range;
            try {
                largest = parseU64(r.largestRaw);
                range = parseU64(i == 0 ? r.firstRangeRaw : r.ackRangeRaw);
            } catch (NumberFormatException e) {
                return new Decoded(List.of(), ResultStatus.FORMAT_CORRUPT,
                        "ACK block carries a value that is not a 64-bit unsigned integer");
            }
            long start = largest - range;
            long end = largest;
            if (i > 0) {
                long gap;
                try {
                    gap = parseU64(r.gapRaw);
                } catch (NumberFormatException e) {
                    return new Decoded(List.of(), ResultStatus.FORMAT_CORRUPT,
                            "ACK gap is not a 64-bit unsigned integer");
                }
                long smallestPrevious = blocks.get(blocks.size() - 1).start;
                end = smallestPrevious - gap - 2;
                start = end - range;
                if (end < 0) {
                    return new Decoded(List.of(), ResultStatus.FORMAT_CORRUPT,
                            "ACK block end underflows: gap=" + gap
                                    + " exceeds previous block (smallest="
                                    + smallestPrevious + ")");
                }
            }
            if (start < 0) {
                return new Decoded(List.of(), ResultStatus.FORMAT_CORRUPT,
                        "ACK block start underflows: largest=" + largest + " range=" + range);
            }
            blocks.add(new Block(start, end));
        }
        for (int i = 0; i < blocks.size(); i++) {
            for (int j = i + 1; j < blocks.size(); j++) {
                Block a = blocks.get(i);
                Block b = blocks.get(j);
                if (a.start <= b.end && b.start <= a.end) {
                    return new Decoded(blocks, ResultStatus.SEMANTIC_NO_SOLUTION,
                            "ACK blocks overlap: [" + a.start + "," + a.end + "] vs ["
                                    + b.start + "," + b.end + "]");
                }
            }
        }
        boolean outOfOrder = prevLargest >= 0 && !blocks.isEmpty()
                && blocks.get(0).end > prevLargest;
        return new Decoded(blocks, ResultStatus.REPLAYED_OK,
                outOfOrder
                        ? "out-of-order ACK: largest acknowledged " + blocks.get(0).end
                                + " advances beyond previously observed " + prevLargest
                        : "in-order ACK range decode");
    }

    /** Classify coverage against confirmed PNs and undecryptable holes. */
    public static ResultStatus coverage(Decoded decoded, Set<Long> confirmed,
                                        Set<Long> holes, boolean[] outHasHole) {
        boolean coversConfirmed = false;
        boolean coversHole = false;
        for (Block b : decoded.blocks) {
            for (long pn = b.start; pn <= b.end && pn >= b.start; pn++) {
                if (confirmed.contains(pn)) {
                    coversConfirmed = true;
                }
                if (holes.contains(pn)) {
                    coversHole = true;
                }
                if (pn == Long.MAX_VALUE) {
                    break;
                }
            }
        }
        outHasHole[0] = coversHole;
        if (coversHole && !coversConfirmed) {
            return ResultStatus.UNVERIFIABLE;
        }
        if (coversHole) {
            return ResultStatus.UNVERIFIABLE;
        }
        return ResultStatus.ACCEPTED;
    }

    static long parseU64(String raw) {
        long v = Long.parseUnsignedLong(raw.trim());
        return v;
    }
}
