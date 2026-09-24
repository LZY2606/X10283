package org.quiccourt.engine;

import java.util.ArrayList;
import java.util.List;
import org.quiccourt.domain.Material;
import org.quiccourt.domain.Params;

/**
 * Key phase / key update tracker (RFC 9000 §6.5, RFC 9001 §4.9), per
 * Application PN space and direction.
 *
 * <p>Commit rule, implemented as state rather than log lines:
 * <ol>
 *   <li>first packet whose key phase bit differs from the active phase and that
 *       decrypts under the <em>next</em> key generation moves to UPDATE_DETECTED
 *       (generation is not committed yet);</li>
 *   <li>a further packet with the new phase bit, decrypting under the new key,
 *       COMMITs the update (Key Phase Confirmation rule). Until then the old key
 *       stays within its grace window;</li>
 *   <li>a single flipped-bit packet that is not corroborated is a MISFLIP:
 *       rejected, generation unchanged;</li>
 *   <li>old-key packets arriving after the grace budget are REJECTED_EXPIRED.</li>
 * </ol>
 * Nothing here commits on a bit flip alone.
 */
public final class KeyPhaseFsm {

    public static final class State {
        public long generation = 0;
        public long phaseBit = 0;
        public boolean pending = false;
        public long pendingGeneration = -1;
        public long newKeyPackets = 0;
        public long oldKeyAfterFlip = 0;
        public final List<String> lineage = new ArrayList<>();

        State() {
            lineage.add("gen=0 kp=0 COMMITTED");
        }
    }

    public static final class Outcome {
        public final ResultStatus status;
        public final long generation;
        public final long phase;
        public final List<Candidate> candidates;
        public final String note;

        Outcome(ResultStatus status, long generation, long phase, List<Candidate> candidates,
                String note) {
            this.status = status;
            this.generation = generation;
            this.phase = phase;
            this.candidates = candidates;
            this.note = note;
        }
    }

    private KeyPhaseFsm() {
    }

    public static Outcome process(Material.Header h, Integer kpBit, Integer successfulGen,
                                  State st, Params p) {
        boolean decrypted = successfulGen != null;
        List<Candidate> cands = candidatesFor(kpBit, successfulGen, st);

        if (!decrypted) {
            return new Outcome(ResultStatus.AMBIGUOUS, st.generation, st.phaseBit, cands,
                    "packet undecryptable: key phase bit is untrusted until decryption, "
                            + "no generation commit");
        }
        long usedGen = successfulGen;
        if (!st.pending) {
            long expectedBit = st.generation & 1L;
            if (kpBit != null && kpBit != expectedBit) {
                if (usedGen == st.generation + 1) {
                    st.pending = true;
                    st.pendingGeneration = usedGen;
                    st.newKeyPackets = 1;
                    st.oldKeyAfterFlip = 0;
                    return new Outcome(ResultStatus.UPDATE_DETECTED, st.generation, kpBit, cands,
                            "key phase bit flipped and packet decrypts under generation "
                                    + usedGen + ": update detected, awaiting confirmation "
                                    + "(generation not committed)");
                }
                if (usedGen == st.generation) {
                    return new Outcome(ResultStatus.REJECTED_MISFLIP, st.generation,
                            expectedBit, cands,
                            "key phase bit flipped (" + kpBit + ") but packet decrypts under "
                                    + "current generation " + usedGen
                                    + ": treated as misflip/reorder, flip rejected");
                }
                return new Outcome(ResultStatus.REJECTED_MISFLIP, st.generation, expectedBit,
                        cands,
                        "key phase bit flipped and decryption generation " + usedGen
                                + " is neither current nor next: misflip rejected");
            }
            if (usedGen != st.generation) {
                return new Outcome(ResultStatus.REJECTED_MISFLIP, st.generation, expectedBit,
                        cands,
                        "decryption under unexpected generation " + usedGen
                                + " without a phase-bit transition: rejected");
            }
            return new Outcome(ResultStatus.ACCEPTED, st.generation, expectedBit, cands,
                    "phase bit matches active generation " + st.generation + ": accepted");
        }

        // Pending update: new key confirms; old key tolerated within grace.
        long expectedNewBit = st.pendingGeneration & 1L;
        if (kpBit != null && kpBit == expectedNewBit && usedGen == st.pendingGeneration) {
            st.newKeyPackets++;
            if (st.newKeyPackets >= 2) {
                st.generation = st.pendingGeneration;
                st.phaseBit = expectedNewBit;
                st.pending = false;
                st.pendingGeneration = -1;
                st.lineage.add("gen=" + st.generation + " kp=" + st.phaseBit + " COMMITTED");
                return new Outcome(ResultStatus.COMMITTED, st.generation, st.phaseBit, cands,
                        "second new-key packet confirms the update (Key Phase Confirmation): "
                                + "generation committed to " + st.generation);
            }
            return new Outcome(ResultStatus.UPDATE_DETECTED, st.generation, expectedNewBit, cands,
                    "new-key packet within pending update (need one more to confirm)");
        }
        if (usedGen == st.generation) {
            st.oldKeyAfterFlip++;
            if (st.oldKeyAfterFlip <= p.oldKeyGracePackets) {
                return new Outcome(ResultStatus.ACCEPTED, st.generation, st.phaseBit, cands,
                        "old-key packet during pending update within grace ("
                                + st.oldKeyAfterFlip + "/" + p.oldKeyGracePackets
                                + "): tolerated, update stays uncommitted");
            }
            return new Outcome(ResultStatus.REJECTED_EXPIRED, st.generation, st.phaseBit, cands,
                    "old-key packet past grace window (" + st.oldKeyAfterFlip + " > "
                            + p.oldKeyGracePackets + "): old key expired, update uncommitted");
        }
        return new Outcome(ResultStatus.REJECTED_MISFLIP, st.generation, st.phaseBit, cands,
                "unexpected generation " + usedGen + " during pending update: rejected");
    }

    private static List<Candidate> candidatesFor(Integer kpBit, Integer successfulGen, State st) {
        List<Candidate> out = new ArrayList<>();
        out.add(new Candidate("gen=" + st.generation + ",kp=" + (st.generation & 1L),
                !st.pending, "active generation"));
        if (st.pending) {
            out.add(new Candidate("gen=" + st.pendingGeneration + ",kp="
                    + (st.pendingGeneration & 1L), false,
                    "pending generation, awaiting confirmation"));
        } else {
            out.add(new Candidate("gen=" + (st.generation + 1) + ",kp="
                    + ((st.generation + 1) & 1L), false,
                    "next generation, only adopted after detected+confirmed update"));
        }
        if (kpBit != null) {
            out.add(new Candidate("kpBitClaim=" + kpBit + ",decryptGen="
                    + (successfulGen == null ? "none" : successfulGen),
                    false, "raw material claim, never adopted on its own"));
        }
        return out;
    }
}
