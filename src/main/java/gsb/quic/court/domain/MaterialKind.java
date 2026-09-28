package gsb.quic.court.domain;

/**
 * Kinds of immutable source material. Every kind preserves its raw representation
 * verbatim; normalisation happens only in the derivation layer.
 */
public enum MaterialKind {
    DATAGRAM("datagram"),
    PACKET_HEADER("packet_header"),
    HP_CANDIDATE("hp_candidate"),
    KEY_EPOCH("key_epoch"),
    CID_EVENT("cid_event"),
    PATH("path"),
    ACK_RANGE("ack_range"),
    DECRYPT_CANDIDATE("decrypt_candidate");

    private final String wire;

    MaterialKind(String wire) {
        this.wire = wire;
    }

    public String wire() {
        return wire;
    }

    public static MaterialKind fromWire(String wire) {
        for (MaterialKind k : values()) {
            if (k.wire.equals(wire)) {
                return k;
            }
        }
        throw new IllegalArgumentException("unknown material kind: " + wire);
    }
}
