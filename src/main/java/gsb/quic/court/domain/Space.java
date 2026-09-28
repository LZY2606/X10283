package gsb.quic.court.domain;

/** QUIC packet number spaces. Recovery state never crosses these boundaries. */
public enum Space {
    INITIAL("Initial"),
    HANDSHAKE("Handshake"),
    APPLICATION("Application");

    private final String label;

    Space(String label) {
        this.label = label;
    }

    public String label() {
        return label;
    }
}
