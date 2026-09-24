package quiccourt.model;

import quiccourt.core.Diagnostic;
import com.fasterxml.jackson.databind.JsonNode;
import java.util.ArrayList;
import java.util.List;

/** Parsed, typed views over immutable material payloads.
 *  All domain quantities carry an explicit unit or coordinate base. */
public final class M {
    private M() {}

    /** Time base for the whole case: microseconds since the case epoch. */
    public static final String TIME_UNIT = "us-since-case-epoch";

    public record DatagramRec(String id, String path, String direction, long arrivalUs, String bytesHex) {}
    public record HeaderRec(String id, String datagramId, String space, long truncatedPn, int pnBits,
                            Boolean keyPhaseBit, String dcid, String scid) {}
    public record HpCandidateRec(String id, String headerId, String keyGenId, String maskHex) {}
    public record KeyGenRec(String id, String space, int generation, String suite, long validFromSeq) {}
    public record DecryptCandidateRec(String id, String headerId, String keyGenId, boolean ok, Long fullPn) {}
    public record CidEventRec(String id, String cid, String action, String path, long cidSeq, long timeUs) {}
    public record PathEventRec(String id, String path, String action, String fourTuple, long timeUs) {}
    public record AckRangeRec(String id, String space, String path, long arrivalUs, List<long[]> ranges) {}

    public record Parsed<T>(T value, List<Diagnostic> diagnostics) {
        public boolean ok() { return value != null; }
    }

    /** Lenient field reader: every miss produces a positioned diagnostic, never a silent default. */
    public static final class Reader {
        private final JsonNode n;
        private final String base;
        public final List<Diagnostic> diags = new ArrayList<>();
        public Reader(JsonNode n, String materialId) { this.n = n; this.base = "material:" + materialId; }

        public String str(String field) {
            JsonNode v = n.get(field);
            if (v == null || !v.isTextual()) { miss(field, "expected string"); return null; }
            return v.asText();
        }
        public Long lng(String field) {
            JsonNode v = n.get(field);
            if (v == null || !v.isIntegralNumber()) { miss(field, "expected integer"); return null; }
            return v.asLong();
        }
        public Integer integer(String field) {
            Long l = lng(field);
            return l == null ? null : l.intValue();
        }
        public Boolean bool(String field) {
            JsonNode v = n.get(field);
            if (v == null || !v.isBoolean()) { miss(field, "expected boolean"); return null; }
            return v.asBoolean();
        }
        private void miss(String field, String why) {
            diags.add(new Diagnostic(base + "#/" + field, "MISSING_FIELD", why));
        }
    }

    public static Parsed<DatagramRec> datagram(Material m) {
        Reader r = new Reader(m.raw(), m.id());
        String path = r.str("path"), dir = r.str("direction"), hex = r.str("bytes_hex");
        Long t = r.lng("arrival_us");
        String unit = r.str("time_unit");
        if (unit != null && !TIME_UNIT.equals(unit))
            r.diags.add(new Diagnostic("material:" + m.id() + "#/time_unit", "UNIT_MISMATCH",
                    "cannot convert '" + unit + "' to " + TIME_UNIT + "; value left in original position"));
        if (path == null || dir == null || hex == null || t == null) return new Parsed<>(null, r.diags);
        return new Parsed<>(new DatagramRec(m.id(), path, dir, t, hex), r.diags);
    }

    public static Parsed<HeaderRec> header(Material m) {
        Reader r = new Reader(m.raw(), m.id());
        String dg = r.str("datagram"), space = r.str("space");
        Long tpn = r.lng("truncated_pn");
        Integer bits = r.integer("pn_bits");
        Boolean kp = r.bool("key_phase_bit"); // optional outside application space
        String dcid = r.str("dcid"), scid = r.str("scid");
        if (dg == null || space == null || tpn == null || bits == null) return new Parsed<>(null, r.diags);
        if (bits < 8 || bits > 32 || bits % 8 != 0)
            r.diags.add(new Diagnostic("material:" + m.id() + "#/pn_bits", "OUT_OF_RANGE", "pn_bits must be 8..32 in whole bytes"));
        return new Parsed<>(new HeaderRec(m.id(), dg, space, tpn, bits, kp, dcid, scid), r.diags);
    }

    public static Parsed<HpCandidateRec> hpCandidate(Material m) {
        Reader r = new Reader(m.raw(), m.id());
        String h = r.str("header"), kg = r.str("key_gen"), mask = r.str("mask_hex");
        if (h == null || kg == null || mask == null) return new Parsed<>(null, r.diags);
        return new Parsed<>(new HpCandidateRec(m.id(), h, kg, mask), r.diags);
    }

    public static Parsed<KeyGenRec> keyGen(Material m) {
        Reader r = new Reader(m.raw(), m.id());
        String space = r.str("space"), suite = r.str("suite");
        Integer gen = r.integer("generation");
        Long vfs = r.lng("valid_from_seq");
        if (space == null || suite == null || gen == null || vfs == null) return new Parsed<>(null, r.diags);
        return new Parsed<>(new KeyGenRec(m.id(), space, gen, suite, vfs), r.diags);
    }

    public static Parsed<DecryptCandidateRec> decryptCandidate(Material m) {
        Reader r = new Reader(m.raw(), m.id());
        String h = r.str("header"), kg = r.str("key_gen");
        Boolean ok = r.bool("ok");
        Long fpn = r.lng("full_pn"); // may be absent when decryption failed
        if (h == null || kg == null || ok == null) return new Parsed<>(null, r.diags);
        return new Parsed<>(new DecryptCandidateRec(m.id(), h, kg, ok, fpn), r.diags);
    }

    public static Parsed<CidEventRec> cidEvent(Material m) {
        Reader r = new Reader(m.raw(), m.id());
        String cid = r.str("cid"), action = r.str("action"), path = r.str("path");
        Long seq = r.lng("cid_seq"), t = r.lng("time_us");
        if (cid == null || action == null || seq == null || t == null) return new Parsed<>(null, r.diags);
        return new Parsed<>(new CidEventRec(m.id(), cid, action, path, seq, t), r.diags);
    }

    public static Parsed<PathEventRec> pathEvent(Material m) {
        Reader r = new Reader(m.raw(), m.id());
        String path = r.str("path"), action = r.str("action"), tuple = r.str("four_tuple");
        Long t = r.lng("time_us");
        if (path == null || action == null || tuple == null || t == null) return new Parsed<>(null, r.diags);
        return new Parsed<>(new PathEventRec(m.id(), path, action, tuple, t), r.diags);
    }

    public static Parsed<AckRangeRec> ackRange(Material m) {
        Reader r = new Reader(m.raw(), m.id());
        String space = r.str("space"), path = r.str("path");
        Long t = r.lng("arrival_us");
        List<long[]> ranges = new ArrayList<>();
        JsonNode arr = m.raw().get("ranges");
        if (arr == null || !arr.isArray() || arr.isEmpty()) {
            r.diags.add(new Diagnostic("material:" + m.id() + "#/ranges", "MISSING_FIELD", "expected non-empty array of [smallest, largest]"));
        } else {
            for (int i = 0; i < arr.size(); i++) {
                JsonNode pair = arr.get(i);
                if (!pair.isArray() || pair.size() != 2 || !pair.get(0).isIntegralNumber() || !pair.get(1).isIntegralNumber()) {
                    r.diags.add(new Diagnostic("material:" + m.id() + "#/ranges/" + i, "FORMAT_CORRUPT", "range must be [smallest, largest] integers"));
                    continue;
                }
                ranges.add(new long[]{pair.get(0).asLong(), pair.get(1).asLong()});
            }
        }
        if (space == null || path == null || t == null || ranges.isEmpty()) return new Parsed<>(null, r.diags);
        return new Parsed<>(new AckRangeRec(m.id(), space, path, t, ranges), r.diags);
    }
}
