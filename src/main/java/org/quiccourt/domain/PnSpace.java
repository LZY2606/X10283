package org.quiccourt.domain;

import java.util.Locale;

/** QUIC packet number spaces (RFC 9000 §12.3). Ordering is fixed and stable. */
public enum PnSpace {
    INITIAL(0, "Initial"),
    HANDSHAKE(1, "Handshake"),
    APPLICATION(2, "Application");

    private final int order;
    private final String label;

    PnSpace(int order, String label) {
        this.order = order;
        this.label = label;
    }

    public int order() {
        return order;
    }

    public String label() {
        return label;
    }

    public static PnSpace fromRaw(String raw) {
        if (raw == null) {
            return null;
        }
        String n = raw.trim().toUpperCase(Locale.ROOT);
        switch (n) {
            case "INITIAL":
            case "0-RTT":
            case "ZERO_RTT":
                return n.equals("0-RTT") || n.equals("ZERO_RTT") ? APPLICATION : INITIAL;
            case "HANDSHAKE":
                return HANDSHAKE;
            case "ONE_RTT":
            case "1-RTT":
            case "APPLICATION":
                return APPLICATION;
            default:
                return null;
        }
    }

    /** 0-RTT packets use the Application packet number space. */
    public static PnSpace forPacketType(String packetType) {
        if (packetType == null) {
            return null;
        }
        switch (packetType.trim().toUpperCase(Locale.ROOT)) {
            case "INITIAL":
                return INITIAL;
            case "HANDSHAKE":
                return HANDSHAKE;
            case "ZERO_RTT":
            case "0-RTT":
            case "ONE_RTT":
            case "1-RTT":
                return APPLICATION;
            default:
                return null;
        }
    }
}
