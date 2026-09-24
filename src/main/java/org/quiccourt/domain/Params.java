package org.quiccourt.domain;

import java.util.Objects;

/**
 * Versioned analysis parameters. Every derived result records the parameter
 * version under which it was computed, so a later revision never rewrites
 * history.
 */
public final class Params {
    public static final String RULE_VERSION = "quic-court-rules-1.0.0";

    public final int version;
    public final long pnWindowDivisor;     // RFC 9000 A.10: 2^(pnBits-1) relative window
    public final long pnMaxCandidates;     // budget for retained legal candidates
    public final long oldKeyGracePackets;  // packets accepted with old key after first new-key packet
    public final long oldKeyGraceMillis;   // time-based grace, 0 => disabled if packets set
    public final long preAnchorEpochs;     // search epochs retained before any anchor exists
    public final boolean fiveTupleCuts;    // must be false: migration never cuts the connection

    public Params(int version, long pnWindowDivisor, long pnMaxCandidates,
                  long oldKeyGracePackets, long oldKeyGraceMillis, long preAnchorEpochs,
                  boolean fiveTupleCuts) {
        this.version = version;
        this.pnWindowDivisor = pnWindowDivisor;
        this.pnMaxCandidates = pnMaxCandidates;
        this.oldKeyGracePackets = oldKeyGracePackets;
        this.oldKeyGraceMillis = oldKeyGraceMillis;
        this.preAnchorEpochs = preAnchorEpochs;
        this.fiveTupleCuts = fiveTupleCuts;
    }

    public static Params v1() {
        // RFC 9000 A.10: half-window recovery (window = 2^pnBits, half = 2^(pnBits-1)).
        return new Params(1, 2, 8, 3, 50, 4, false);
    }

    public String fingerprint() {
        return RULE_VERSION + "|w/" + pnWindowDivisor
                + "|cap/" + pnMaxCandidates
                + "|gkp/" + oldKeyGracePackets
                + "|gms/" + oldKeyGraceMillis
                + "|ep/" + preAnchorEpochs
                + "|5t/" + fiveTupleCuts;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof Params)) {
            return false;
        }
        Params p = (Params) o;
        return version == p.version && pnWindowDivisor == p.pnWindowDivisor
                && pnMaxCandidates == p.pnMaxCandidates
                && oldKeyGracePackets == p.oldKeyGracePackets
                && oldKeyGraceMillis == p.oldKeyGraceMillis
                && preAnchorEpochs == p.preAnchorEpochs
                && fiveTupleCuts == p.fiveTupleCuts;
    }

    @Override
    public int hashCode() {
        return Objects.hash(version, pnWindowDivisor, pnMaxCandidates,
                oldKeyGracePackets, oldKeyGraceMillis, preAnchorEpochs, fiveTupleCuts);
    }
}
