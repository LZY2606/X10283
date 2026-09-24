package org.quiccourt.domain;

/**
 * A measured/raw quantity: original representation is preserved verbatim; the
 * derived layer may normalize it. Values that cannot be converted stay in place
 * (normalized == null) with a diagnostic attached — they are never dropped.
 */
public final class Quant {
    private final String raw;
    private final String unit;
    private final Double normalized;
    private final String canonicalUnit;
    private final String basis;

    public Quant(String raw, String unit, Double normalized, String canonicalUnit, String basis) {
        this.raw = raw;
        this.unit = unit;
        this.normalized = normalized;
        this.canonicalUnit = canonicalUnit;
        this.basis = basis;
    }

    public String raw() {
        return raw;
    }

    public String unit() {
        return unit;
    }

    public Double normalized() {
        return normalized;
    }

    public String canonicalUnit() {
        return canonicalUnit;
    }

    public String basis() {
        return basis;
    }
}
