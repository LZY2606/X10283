package org.quiccourt.domain;

/** Capture direction, relative to the endpoint holding the trace. */
public enum Direction {
    RX,
    TX;

    public static Direction fromRaw(String raw) {
        if (raw == null) {
            return null;
        }
        switch (raw.trim().toUpperCase()) {
            case "RX":
            case "IN":
            case "RECV":
                return RX;
            case "TX":
            case "OUT":
            case "SEND":
                return TX;
            default:
                return null;
        }
    }
}
