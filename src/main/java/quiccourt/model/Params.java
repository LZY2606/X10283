package quiccourt.model;

/** Versioned computation parameters. Every computation records the version it ran under. */
public record Params(String version, int pnBits, int ambiguityWindows, int gracePackets,
                     int confirmPackets, long budgetMaxOps) {
    public static Params v1() {
        return new Params("params-v1", 16, 1, 3, 2, 100_000);
    }
}
