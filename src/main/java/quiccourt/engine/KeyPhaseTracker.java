package quiccourt.engine;

import java.util.ArrayList;
import java.util.List;

/** Tracks key-phase trajectory for the application space.
 *  A phase flip is only committed after successful decryption with the next
 *  generation AND the confirmation rule (N consecutive packets with the new
 *  phase). Old keys stay usable inside a grace window; packets that decrypt
 *  under no candidate form undecryptable gaps. */
public final class KeyPhaseTracker {

    public record Params(int confirmPackets, int gracePackets) {
        public static Params defaults() { return new Params(2, 3); }
    }

    /** One packet observation, pre-sorted by the caller in stable order. */
    public record Packet(String headerId, long arrivalUs, boolean phaseBit,
                         List<Attempt> attempts) {}

    /** Decryption attempt of one packet under one key generation. */
    public record Attempt(String candidateId, int generation, boolean ok, Long fullPn) {}

    public record Verdict(String headerId, long arrivalUs, String outcome, int generation,
                          String candidateId, String reason) {}
    // outcome: COMMITTED | GRACE_OLD_KEY | FLIP_PENDING | FLIP_COMMITTED |
    //          FALSE_FLIP_REJECTED | UNDECRYPTABLE_GAP

    public record Track(List<Verdict> verdicts, List<int[]> committedGenerations) {
        /** committedGenerations: [generation, fromPacketIndex] segments */
    }

    public static Track run(List<Packet> packets, Params params) {
        List<Verdict> verdicts = new ArrayList<>();
        List<int[]> segments = new ArrayList<>();
        int currentGen = 0;
        int pendingGen = -1;
        int pendingStreak = 0;
        int sinceCommit = 0; // packets observed since the last committed update
        boolean anyCommit = false;
        segments.add(new int[]{0, 0});

        for (int i = 0; i < packets.size(); i++) {
            Packet p = packets.get(i);
            boolean currentPhase = (currentGen & 1) == 1;
            Attempt atCurrent = best(p.attempts(), currentGen);
            Attempt atNext = best(p.attempts(), currentGen + 1);
            Attempt atPrev = currentGen > 0 ? best(p.attempts(), currentGen - 1) : null;
            boolean inGrace = anyCommit && sinceCommit < params.gracePackets();

            if (p.phaseBit() == currentPhase) {
                if (ok(atCurrent)) {
                    verdicts.add(new Verdict(p.headerId(), p.arrivalUs(), "COMMITTED", currentGen,
                            atCurrent.candidateId(), "phase bit matches committed generation " + currentGen));
                    pendingGen = -1; pendingStreak = 0;
                } else if (ok(atPrev) && inGrace) {
                    verdicts.add(new Verdict(p.headerId(), p.arrivalUs(), "GRACE_OLD_KEY", currentGen - 1,
                            atPrev.candidateId(), "old generation accepted inside grace window ("
                            + sinceCommit + " < " + params.gracePackets() + ")"));
                } else {
                    verdicts.add(new Verdict(p.headerId(), p.arrivalUs(), "UNDECRYPTABLE_GAP", currentGen,
                            null, "no candidate key decrypts this packet; gap preserved"));
                }
                sinceCommit++;
                continue;
            }

            // Phase bit differs from the committed generation: a flip stays a
            // candidate until decryption succeeds and the confirmation rule is met.
            if (ok(atNext)) {
                if (pendingGen != currentGen + 1) { pendingGen = currentGen + 1; pendingStreak = 0; }
                pendingStreak++;
                if (pendingStreak >= params.confirmPackets()) {
                    currentGen = pendingGen;
                    pendingGen = -1;
                    pendingStreak = 0;
                    sinceCommit = 0;
                    anyCommit = true;
                    segments.add(new int[]{currentGen, i});
                    verdicts.add(new Verdict(p.headerId(), p.arrivalUs(), "FLIP_COMMITTED", currentGen,
                            atNext.candidateId(), "decrypt ok under gen " + currentGen
                            + " and confirmation rule met (" + params.confirmPackets() + " packets)"));
                    continue;
                }
                verdicts.add(new Verdict(p.headerId(), p.arrivalUs(), "FLIP_PENDING", pendingGen,
                        atNext.candidateId(), "decrypt ok under gen " + pendingGen
                        + " but confirmation " + pendingStreak + "/" + params.confirmPackets()));
                sinceCommit++;
                continue;
            }
            if (ok(atPrev) && inGrace) {
                verdicts.add(new Verdict(p.headerId(), p.arrivalUs(), "GRACE_OLD_KEY", currentGen - 1,
                        atPrev.candidateId(), "old phase bit, old generation accepted inside grace window ("
                        + sinceCommit + " < " + params.gracePackets() + ")"));
                sinceCommit++;
                continue;
            }
            if (ok(atCurrent)) {
                verdicts.add(new Verdict(p.headerId(), p.arrivalUs(), "FALSE_FLIP_REJECTED", currentGen,
                        atCurrent.candidateId(), "phase bit flipped but new-generation key fails; old key decrypts, flip not committed"));
                sinceCommit++;
                continue;
            }
            verdicts.add(new Verdict(p.headerId(), p.arrivalUs(), "UNDECRYPTABLE_GAP", currentGen,
                    null, "flipped phase with no working candidate; gap preserved"));
            sinceCommit++;
        }
        return new Track(verdicts, segments);
    }

    private static boolean ok(Attempt a) { return a != null && a.ok(); }

    private static Attempt best(List<Attempt> attempts, int gen) {
        for (Attempt a : attempts) if (a.generation() == gen && a.ok()) return a;
        for (Attempt a : attempts) if (a.generation() == gen) return a;
        return null;
    }
}
