package gsb.quic.court.domain;

/**
 * A domain quantity that always carries its unit or coordinate basis.
 * The raw representation is retained so an unconvertible value stays in place
 * with a diagnostic rather than being silently dropped for a chart.
 */
public record Quant(String raw, String unit, Double value) {

    public static Quant of(String raw, String unit) {
        return new Quant(raw, unit, null);
    }

    public boolean isConvertible() {
        return value != null;
    }

    /** Normalise a timestamp to microseconds. Recognises us/ns/ms/s suffixes or bare us. */
    public static Quant timestamp(String raw) {
        String s = raw.trim();
        String unit = "us";
        double mult = 1.0d;
        String lower = s.toLowerCase();
        String num = s;
        if (lower.endsWith("us")) {
            num = s.substring(0, s.length() - 2);
        } else if (lower.endsWith("µs")) {
            num = s.substring(0, s.length() - 2);
        } else if (lower.endsWith("ns")) {
            unit = "us";
            mult = 1.0d / 1000.0d;
            num = s.substring(0, s.length() - 2);
        } else if (lower.endsWith("ms")) {
            unit = "us";
            mult = 1000.0d;
            num = s.substring(0, s.length() - 2);
        } else if (lower.endsWith("s")) {
            unit = "us";
            mult = 1_000_000.0d;
            num = s.substring(0, s.length() - 1);
        }
        try {
            return new Quant(raw, unit, Double.parseDouble(num.trim()) * mult);
        } catch (NumberFormatException e) {
            return new Quant(raw, unit, null);
        }
    }
}
