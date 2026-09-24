package org.quiccourt.engine;

/** One legal candidate value within a derived result. */
public final class Candidate {
    public final String value;
    public final boolean adopted;
    public final String reason;

    public Candidate(String value, boolean adopted, String reason) {
        this.value = value;
        this.adopted = adopted;
        this.reason = reason;
    }

    public Candidate withAdoption(boolean adopted) {
        return new Candidate(value, adopted, reason);
    }
}
