package quiccourt;

import com.fasterxml.jackson.databind.JsonNode;

import java.util.ArrayList;
import java.util.List;

/**
 * Domain model. Raw representations are preserved verbatim in materials;
 * this layer only derives normalized views. Unconvertible values keep their
 * raw form and carry a diagnostic — they are never replaced by defaults.
 */
public final class Model {
    private Model() {}

    /** A quantity with unit / coordinate basis. value==null means unconvertible; raw is authoritative. */
    public record Quantity(String raw, Double value, String unit, String basis) {
        public boolean convertible() { return value != null; }
    }

    public record AckRange(long start, long end) {}

    public record DecryptTry(int generation, boolean success) {}

    public record Datagram(
            String materialId,
            String rawBytesHex,
            Quantity capturedAt,
            String direction,          // c2s | s2c
            String pathId,
            String space,              // initial | handshake | application
            Quantity truncatedPn,
            int pnLengthBytes,
            int keyPhaseBit,
            List<String> hpCandidates,
            String cid,
            List<DecryptTry> tries,
            List<AckRange> acks) {}

    /** Parse a quantity node {"raw": "...", "basis": "..."} keeping raw form; unit inferred from suffix. */
    public static Quantity parseQuantity(JsonNode n, String defaultBasis, List<Diag> diags, String pos) {
        if (n == null || !n.hasNonNull("raw")) {
            diags.add(new Diag(pos, "QUANTITY_MISSING", "quantity node missing raw value"));
            return new Quantity(null, null, null, defaultBasis);
        }
        String raw = n.get("raw").asText();
        String basis = n.hasNonNull("basis") ? n.get("basis").asText() : defaultBasis;
        try {
            String t = raw.trim();
            if (t.startsWith("t+")) {
                String rest = t.substring(2);
                if (rest.endsWith("ms")) return new Quantity(raw, Double.parseDouble(rest.substring(0, rest.length() - 2)), "ms", basis);
                if (rest.endsWith("us")) return new Quantity(raw, Double.parseDouble(rest.substring(0, rest.length() - 2)) / 1000.0, "ms", basis);
                if (rest.endsWith("s")) return new Quantity(raw, Double.parseDouble(rest.substring(0, rest.length() - 1)) * 1000.0, "ms", basis);
                throw new NumberFormatException("unknown time suffix");
            }
            if (t.startsWith("0x") || t.startsWith("0X")) return new Quantity(raw, (double) Long.parseUnsignedLong(t.substring(2), 16), "count", basis);
            return new Quantity(raw, Double.parseDouble(t), "count", basis);
        } catch (RuntimeException e) {
            diags.add(new Diag(pos, "QUANTITY_UNCONVERTIBLE", "cannot normalize '" + raw + "'; raw value kept in place"));
            return new Quantity(raw, null, null, basis);
        }
    }

    public static Datagram parseDatagram(String materialId, JsonNode n, List<Diag> diags) {
        String p = "/materials/" + materialId;
        String space = text(n, "space", "application");
        String dir = text(n, "direction", "c2s");
        Quantity at = parseQuantity(n.get("capturedAt"), "conn_epoch", diags, p + "/capturedAt/raw");
        Quantity tpn = parseQuantity(n.get("truncatedPn"), "pn_space:" + space, diags, p + "/truncatedPn/raw");
        int pnLen = n.hasNonNull("pnLengthBytes") ? n.get("pnLengthBytes").asInt() : -1;
        int phase = n.hasNonNull("keyPhaseBit") ? n.get("keyPhaseBit").asInt() : -1;
        List<String> hp = new ArrayList<>();
        if (n.has("hpCandidates")) n.get("hpCandidates").forEach(x -> hp.add(x.asText()));
        List<DecryptTry> tries = new ArrayList<>();
        if (n.has("decryptCandidates")) {
            int i = 0;
            for (JsonNode t : n.get("decryptCandidates")) {
                tries.add(new DecryptTry(t.get("generation").asInt(), "success".equals(t.get("result").asText())));
                i++;
            }
        }
        List<AckRange> acks = new ArrayList<>();
        if (n.has("ackRanges")) {
            int i = 0;
            for (JsonNode r : n.get("ackRanges")) {
                List<Diag> sub = new ArrayList<>();
                Quantity s = parseQuantity(r.get("start"), "pn_space:" + space, sub, p + "/ackRanges/" + i + "/start/raw");
                Quantity e = parseQuantity(r.get("end"), "pn_space:" + space, sub, p + "/ackRanges/" + i + "/end/raw");
                diags.addAll(sub);
                if (s.convertible() && e.convertible()) acks.add(new AckRange(s.value().longValue(), e.value().longValue()));
                i++;
            }
        }
        return new Datagram(materialId, text(n, "rawBytesHex", ""), at, dir, text(n, "path", "path-1"),
                space, tpn, pnLen, phase, hp, text(n, "cid", ""), tries, acks);
    }

    static String text(JsonNode n, String f, String dflt) {
        return n.hasNonNull(f) ? n.get(f).asText() : dflt;
    }
}
