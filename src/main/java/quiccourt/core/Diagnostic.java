package quiccourt.core;

/** A positioned diagnostic. position is a stable locator such as
 *  "material:mat-0007#/truncated_pn" or "xfer#/events/3". Never null. */
public record Diagnostic(String position, String code, String message) {
    public Diagnostic {
        if (position == null || position.isBlank()) position = "<unknown>";
        if (code == null || code.isBlank()) code = "DIAGNOSTIC";
        if (message == null) message = "";
    }
    @Override public String toString() { return code + " @ " + position + ": " + message; }
}
