package quiccourt.domain;

/** Versioned rule parameters. Every computation records the version it ran under. */
public record Params(int pnBits, long keyGraceNs, int recoveryBudget, String version) {
    public static Params v1() {
        return new Params(8, 3_000_000L, 64, "pn-court-rules/v1");
    }
}
