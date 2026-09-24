package org.quiccourt.engine;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.quiccourt.domain.DiagClass;
import org.quiccourt.domain.Diagnostic;
import org.quiccourt.domain.Direction;
import org.quiccourt.domain.Material;
import org.quiccourt.domain.MaterialBundle;
import org.quiccourt.domain.PnSpace;
import org.quiccourt.domain.Quant;

/**
 * Parses the team capture JSON into the immutable material layer.
 *
 * <p>Failure kinds stay distinct: FORMAT_CORRUPT (cannot parse bytes/shape),
 * SEMANTIC_NO_SOLUTION (parseable but impossible). BUDGET_EXHAUSTED is produced
 * later by the engine. Any ERROR rejects the whole package, with located
 * diagnostics and the affected objects named.
 */
public final class BundleParser {
    private static final ObjectMapper MAPPER = new ObjectMapper();

    public static final class ParseOutcome {
        public final MaterialBundle bundle;
        public final List<Diagnostic> diagnostics;

        ParseOutcome(MaterialBundle bundle, List<Diagnostic> diagnostics) {
            this.bundle = bundle;
            this.diagnostics = List.copyOf(diagnostics);
        }

        public boolean accepted() {
            return bundle != null;
        }
    }

    public ParseOutcome parse(String json) {
        List<Diagnostic> diags = new ArrayList<>();
        JsonNode root;
        try {
            root = MAPPER.readTree(json);
        } catch (Exception e) {
            diags.add(Diagnostic.error(DiagClass.FORMAT_CORRUPT, "JSON_UNPARSEABLE",
                    "capture package is not valid JSON: " + e.getMessage(),
                    "$", truncate(json, 120), List.of()));
            return new ParseOutcome(null, diags);
        }
        if (root == null || !root.isObject()) {
            diags.add(Diagnostic.error(DiagClass.FORMAT_CORRUPT, "ROOT_NOT_OBJECT",
                    "capture package root must be an object", "$", null, List.of()));
            return new ParseOutcome(null, diags);
        }

        String label = requireText(root, "label", "$", diags);
        String basis = optionalText(root, "timeBasis", "capture-epoch(ms)");

        List<Material.PathInfo> paths = parsePaths(root, basis, diags);
        List<Material.Datagram> datagrams = parseDatagrams(root, basis, diags);
        List<Material.HpCandidate> hp = parseHp(root, diags);
        List<Material.DecryptionCandidate> dc = parseDecryption(root, diags);
        List<Material.Header> headers = parseHeaders(root, diags);
        List<Material.CidEvent> cids = parseCids(root, basis, diags);
        List<Material.AckRange> acks = parseAcks(root, diags);

        crossCheck(datagrams, headers, paths, hp, dc, acks, cids, diags);

        if (hasError(diags)) {
            return new ParseOutcome(null, diags);
        }
        List<Diagnostic> warnings = onlyNonErrors(diags);
        return new ParseOutcome(new MaterialBundle(label, basis, datagrams, headers, hp, dc,
                cids, paths, acks, warnings), diags);
    }

    // ------------------------------------------------------------------ paths

    private List<Material.PathInfo> parsePaths(JsonNode root, String basis, List<Diagnostic> errs) {
        List<Material.PathInfo> out = new ArrayList<>();
        JsonNode arr = arrayOrError(root, "paths", errs);
        if (arr == null) {
            return out;
        }
        for (int i = 0; i < arr.size(); i++) {
            String p = "$.paths[" + i + "]";
            JsonNode n = arr.get(i);
            String id = requireId(n, p, errs);
            String la = requireText(n, "localAddr", p, errs);
            String lp = requireText(n, "localPort", p, errs);
            String ra = requireText(n, "remoteAddr", p, errs);
            String rp = requireText(n, "remotePort", p, errs);
            Quant fs = parseQuant(n, "firstSeen", basis, p, errs);
            if (id != null) {
                out.add(new Material.PathInfo(id, la, lp, ra, rp, fs));
            }
        }
        return out;
    }

    private List<Material.Datagram> parseDatagrams(JsonNode root, String basis,
                                                   List<Diagnostic> errs) {
        List<Material.Datagram> out = new ArrayList<>();
        JsonNode arr = arrayOrError(root, "datagrams", errs);
        if (arr == null) {
            return out;
        }
        for (int i = 0; i < arr.size(); i++) {
            String p = "$.datagrams[" + i + "]";
            JsonNode n = arr.get(i);
            String id = requireId(n, p, errs);
            Quant t = parseQuant(n, "time", basis, p, errs);
            Direction dir = parseDirection(n, p, errs);
            String pathId = requireText(n, "pathId", p, errs);
            String hex = requireHex(n, "rawHex", p, errs, 1);
            if (id != null) {
                out.add(new Material.Datagram(id, t, dir, pathId, hex, basis));
            }
        }
        return out;
    }

    private List<Material.HpCandidate> parseHp(JsonNode root, List<Diagnostic> errs) {
        List<Material.HpCandidate> out = new ArrayList<>();
        JsonNode arr = root.get("hpCandidates");
        if (arr == null) {
            return out;
        }
        if (!arr.isArray()) {
            errs.add(Diag.fmt("'hpCandidates' must be an array", "$.hpCandidates", null));
            return out;
        }
        for (int i = 0; i < arr.size(); i++) {
            String p = "$.hpCandidates[" + i + "]";
            JsonNode n = arr.get(i);
            String id = requireId(n, p, errs);
            String label = optionalText(n, "label", id);
            String sample = requireHex(n, "sampleHex", p, errs, 0);
            String mask = requireHex(n, "maskHex", p, errs, 0);
            if (id != null) {
                out.add(new Material.HpCandidate(id, label, sample, mask));
            }
        }
        return out;
    }

    private List<Material.DecryptionCandidate> parseDecryption(JsonNode root,
                                                               List<Diagnostic> errs) {
        List<Material.DecryptionCandidate> out = new ArrayList<>();
        JsonNode arr = root.get("decryptionCandidates");
        if (arr == null) {
            return out;
        }
        if (!arr.isArray()) {
            errs.add(Diag.fmt("'decryptionCandidates' must be an array",
                    "$.decryptionCandidates", null));
            return out;
        }
        for (int i = 0; i < arr.size(); i++) {
            String p = "$.decryptionCandidates[" + i + "]";
            JsonNode n = arr.get(i);
            String id = requireId(n, p, errs);
            Long gen = requireLong(n, "keyGeneration", p, errs);
            String spaceRaw = requireText(n, "space", p, errs);
            PnSpace sp = null;
            if (spaceRaw != null) {
                sp = PnSpace.fromRaw(spaceRaw);
                if (sp == null) {
                    errs.add(Diag.sem("unknown packet number space '" + spaceRaw + "'",
                            p + ".space", spaceRaw));
                }
            }
            Boolean ok = requireBool(n, "success", p, errs);
            String note = optionalText(n, "note", "");
            if (id != null && gen != null && ok != null) {
                out.add(new Material.DecryptionCandidate(id, gen.intValue(), sp, ok, note));
            }
        }
        return out;
    }

    // ---------------------------------------------------------------- headers

    private List<Material.Header> parseHeaders(JsonNode root, List<Diagnostic> errs) {
        List<Material.Header> out = new ArrayList<>();
        JsonNode arr = arrayOrError(root, "headers", errs);
        if (arr == null) {
            return out;
        }
        for (int i = 0; i < arr.size(); i++) {
            String p = "$.headers[" + i + "]";
            JsonNode n = arr.get(i);
            String id = requireId(n, p, errs);
            String dg = requireText(n, "datagramId", p, errs);
            String ptype = requireText(n, "packetType", p, errs);
            PnSpace sp = ptype == null ? null : PnSpace.forPacketType(ptype);
            if (ptype != null && sp == null) {
                errs.add(Diag.sem("unknown packet type '" + ptype + "'", p + ".packetType", ptype));
            }
            String tpn = requireHex(n, "truncatedPn", p, errs, 1);
            // pnBytes is optional: header protection may not be confirmed yet,
            // in which case the length field is uncertain and recovery must
            // enumerate 1..available-byte lengths.
            Long pnBytes = null;
            if (n.hasNonNull("pnBytes")) {
                pnBytes = requireLong(n, "pnBytes", p, errs);
                if (pnBytes != null && (pnBytes < 1 || pnBytes > 4)) {
                    errs.add(Diag.sem("pnBytes must be 1..4, got " + pnBytes,
                            p + ".pnBytes", String.valueOf(pnBytes)));
                    pnBytes = null;
                }
                if (tpn != null && pnBytes != null && tpn.length() / 2 != pnBytes) {
                    errs.add(Diag.sem("truncated PN length (" + (tpn.length() / 2)
                            + " bytes) disagrees with pnBytes (" + pnBytes + ")",
                            p + ".truncatedPn", tpn));
                }
            }
            if (tpn != null && tpn.length() / 2 > 4) {
                errs.add(Diag.sem("truncated PN has more than 4 trailing bytes",
                        p + ".truncatedPn", tpn));
            }
            String hpId = optionalText(n, "hpCandidateId", null);
            Integer kp = null;
            if (n.hasNonNull("keyPhaseBit")) {
                JsonNode k = n.get("keyPhaseBit");
                if (!k.isInt() || (k.intValue() != 0 && k.intValue() != 1)) {
                    errs.add(Diag.fmt("keyPhaseBit must be 0 or 1", p + ".keyPhaseBit",
                            String.valueOf(k)));
                } else {
                    kp = k.intValue();
                }
            }
            String scid = optionalText(n, "scid", "");
            String dcid = optionalText(n, "dcid", "");
            List<String> dcs = new ArrayList<>();
            JsonNode dcn = n.get("decryptionCandidateIds");
            if (dcn != null) {
                if (!dcn.isArray()) {
                    errs.add(Diag.fmt("decryptionCandidateIds must be an array",
                            p + ".decryptionCandidateIds", null));
                } else {
                    for (JsonNode x : dcn) {
                        dcs.add(x.asText());
                    }
                }
            }
            boolean decryptable = !n.has("decryptable") || n.get("decryptable").asBoolean(true);
            if (id != null && dg != null && tpn != null) {
                out.add(new Material.Header(id, dg, ptype, sp, tpn,
                        pnBytes == null ? null : pnBytes.intValue(), hpId, kp,
                        scid, dcid, dcs, decryptable));
            }
        }
        return out;
    }

    // ------------------------------------------------------------------- cids

    private List<Material.CidEvent> parseCids(JsonNode root, String basis, List<Diagnostic> errs) {
        List<Material.CidEvent> out = new ArrayList<>();
        JsonNode arr = root.get("cidEvents");
        if (arr == null) {
            return out;
        }
        if (!arr.isArray()) {
            errs.add(Diag.fmt("'cidEvents' must be an array", "$.cidEvents", null));
            return out;
        }
        for (int i = 0; i < arr.size(); i++) {
            String p = "$.cidEvents[" + i + "]";
            JsonNode n = arr.get(i);
            String id = requireId(n, p, errs);
            String cid = requireHex(n, "cid", p, errs, 1);
            String role = requireText(n, "role", p, errs);
            if (role != null && !role.equals("ISSUE") && !role.equals("USE")
                    && !role.equals("RETIRE")) {
                errs.add(Diag.sem("CID role must be ISSUE/USE/RETIRE, got " + role,
                        p + ".role", role));
                role = null;
            }
            String path = optionalText(n, "pathId", null);
            Quant t = parseQuant(n, "time", basis, p, errs);
            String dg = optionalText(n, "datagramId", null);
            Integer rpt = null;
            if (n.hasNonNull("retirePriorTo")) {
                Long v = requireLong(n, "retirePriorTo", p, errs);
                if (v != null) {
                    rpt = v.intValue();
                }
            }
            if (id != null && cid != null && role != null) {
                out.add(new Material.CidEvent(id, cid, role, path, t, dg, rpt));
            }
        }
        return out;
    }

    // ------------------------------------------------------------------- acks

    private List<Material.AckRange> parseAcks(JsonNode root, List<Diagnostic> errs) {
        List<Material.AckRange> out = new ArrayList<>();
        JsonNode arr = root.get("ackRanges");
        if (arr == null) {
            return out;
        }
        if (!arr.isArray()) {
            errs.add(Diag.fmt("'ackRanges' must be an array", "$.ackRanges", null));
            return out;
        }
        for (int i = 0; i < arr.size(); i++) {
            String p = "$.ackRanges[" + i + "]";
            JsonNode n = arr.get(i);
            String id = requireId(n, p, errs);
            String hid = requireText(n, "headerId", p, errs);
            String largest = requireUintText(n, "largest", p, errs);
            String firstRange = requireUintText(n, "firstRange", p, errs);
            String gap = optionalText(n, "gap", null);
            String range = optionalText(n, "ackRange", null);
            if ((gap == null) != (range == null)) {
                errs.add(Diag.sem("'gap' and 'ackRange' must appear together", p, null));
                gap = null;
                range = null;
            }
            String delayRaw = optionalText(n, "ackDelay", "0");
            String delayUnit = optionalText(n, "ackDelayUnit", "ms");
            if (id != null && hid != null && largest != null && firstRange != null) {
                out.add(new Material.AckRange(id, hid, largest, gap, range, firstRange,
                        delayRaw, delayUnit));
            }
        }
        return out;
    }

    // ------------------------------------------------------------- crosscheck

    private void crossCheck(List<Material.Datagram> dgs, List<Material.Header> hs,
                            List<Material.PathInfo> paths, List<Material.HpCandidate> hp,
                            List<Material.DecryptionCandidate> dc, List<Material.AckRange> acks,
                            List<Material.CidEvent> cids, List<Diagnostic> errs) {
        Set<String> dgIds = new HashSet<>();
        for (Material.Datagram d : dgs) {
            if (!dgIds.add(d.id)) {
                errs.add(Diag.sem("duplicate datagram id", "$.datagrams", d.id));
            }
        }
        Set<String> pathIds = new HashSet<>();
        for (Material.PathInfo p : paths) {
            if (!pathIds.add(p.id)) {
                errs.add(Diag.sem("duplicate path id", "$.paths", p.id));
            }
        }
        for (Material.Datagram d : dgs) {
            if (!pathIds.contains(d.pathId)) {
                errs.add(Diag.sem("datagram references unknown path '" + d.pathId + "'",
                        "$.datagrams[?].pathId", d.id));
            }
        }
        Set<String> hpIds = new HashSet<>();
        for (Material.HpCandidate h : hp) {
            hpIds.add(h.id);
        }
        Set<String> dcIds = new HashSet<>();
        for (Material.DecryptionCandidate d : dc) {
            dcIds.add(d.id);
        }
        Set<String> headerIds = new HashSet<>();
        for (Material.Header h : hs) {
            if (!headerIds.add(h.id)) {
                errs.add(Diag.sem("duplicate header id", "$.headers", h.id));
            }
            if (!dgIds.contains(h.datagramId)) {
                errs.add(Diag.sem("header references unknown datagram '" + h.datagramId + "'",
                        "$.headers[?].datagramId", h.id));
            }
            if (h.headerProtectionCandidateId != null
                    && !hpIds.contains(h.headerProtectionCandidateId)) {
                errs.add(Diag.sem("header references unknown hp candidate '"
                        + h.headerProtectionCandidateId + "'",
                        "$.headers[?].hpCandidateId", h.id));
            }
            for (String d : h.decryptionCandidateIds) {
                if (!dcIds.contains(d)) {
                    errs.add(Diag.sem("header references unknown decryption candidate '" + d + "'",
                            "$.headers[?].decryptionCandidateIds", h.id));
                }
            }
        }
        for (Material.AckRange a : acks) {
            if (!headerIds.contains(a.headerId)) {
                errs.add(Diag.sem("ACK range references unknown header '" + a.headerId + "'",
                        "$.ackRanges[?].headerId", a.id));
            }
        }
        for (Material.CidEvent c : cids) {
            if (c.boundPathId != null && !pathIds.contains(c.boundPathId)) {
                errs.add(Diag.sem("CID event references unknown path '" + c.boundPathId + "'",
                        "$.cidEvents[?].pathId", c.id));
            }
        }
    }

    // ----------------------------------------------------------------- utils

    private static boolean hasError(List<Diagnostic> ds) {
        for (Diagnostic d : ds) {
            if (d.severity() == org.quiccourt.domain.Severity.ERROR) {
                return true;
            }
        }
        return false;
    }

    private static List<Diagnostic> onlyNonErrors(List<Diagnostic> ds) {
        List<Diagnostic> out = new ArrayList<>();
        for (Diagnostic d : ds) {
            if (d.severity() != org.quiccourt.domain.Severity.ERROR) {
                out.add(d);
            }
        }
        return out;
    }

    private static JsonNode arrayOrError(JsonNode parent, String field, List<Diagnostic> errs) {
        JsonNode n = parent.get(field);
        if (n == null || !n.isArray()) {
            errs.add(Diag.fmt("missing or non-array '" + field + "'", "$." + field, null));
            return null;
        }
        return n;
    }

    private static String requireId(JsonNode n, String path, List<Diagnostic> errs) {
        String v = requireText(n, "id", path, errs);
        if (v != null && !v.matches("[A-Za-z0-9_.:-]{1,80}")) {
            errs.add(Diag.fmt("id must match [A-Za-z0-9_.:-]{1,80}", path + ".id", v));
            return null;
        }
        return v;
    }

    private static String requireText(JsonNode n, String field, String path,
                                      List<Diagnostic> errs) {
        JsonNode v = n.get(field);
        if (v == null || v.isNull()) {
            errs.add(Diag.fmt("missing field '" + field + "'", path + "." + field, null));
            return null;
        }
        if (!v.isTextual() || v.asText().isBlank()) {
            errs.add(Diag.fmt("field '" + field + "' must be a non-empty string",
                    path + "." + field, String.valueOf(v)));
            return null;
        }
        return v.asText();
    }

    private static String optionalText(JsonNode n, String field, String fallback) {
        JsonNode v = n.get(field);
        return v == null || v.isNull() || !v.isTextual() ? fallback : v.asText();
    }

    private static Boolean requireBool(JsonNode n, String field, String path,
                                       List<Diagnostic> errs) {
        JsonNode v = n.get(field);
        if (v == null || v.isNull()) {
            errs.add(Diag.fmt("missing field '" + field + "'", path + "." + field, null));
            return null;
        }
        if (!v.isBoolean()) {
            errs.add(Diag.fmt("field '" + field + "' must be boolean", path + "." + field,
                    String.valueOf(v)));
            return null;
        }
        return v.booleanValue();
    }

    private static Long requireLong(JsonNode n, String field, String path,
                                    List<Diagnostic> errs) {
        JsonNode v = n.get(field);
        if (v == null || v.isNull()) {
            errs.add(Diag.fmt("missing field '" + field + "'", path + "." + field, null));
            return null;
        }
        if (!v.isIntegralNumber()) {
            errs.add(Diag.fmt("field '" + field + "' must be an integer", path + "." + field,
                    String.valueOf(v)));
            return null;
        }
        if (v.longValue() < 0) {
            errs.add(Diag.sem("field '" + field + "' must be non-negative",
                    path + "." + field, String.valueOf(v)));
            return null;
        }
        return v.longValue();
    }

    private static String requireUintText(JsonNode n, String field, String path,
                                          List<Diagnostic> errs) {
        String v = requireText(n, field, path, errs);
        if (v != null && !v.matches("\\d{1,20}")) {
            errs.add(Diag.fmt("field '" + field + "' must be a base-10 unsigned integer",
                    path + "." + field, v));
            return null;
        }
        return v;
    }

    private static String requireHex(JsonNode n, String field, String path,
                                     List<Diagnostic> errs, int minBytes) {
        String v = requireText(n, field, path, errs);
        if (v == null) {
            return null;
        }
        String h = v.startsWith("0x") || v.startsWith("0X") ? v.substring(2) : v;
        if (h.isEmpty() || h.length() % 2 != 0 || !h.matches("[0-9a-fA-F]+")) {
            errs.add(Diag.fmt("field '" + field + "' must be even-length hex",
                    path + "." + field, v));
            return null;
        }
        if (h.length() / 2 < minBytes) {
            errs.add(Diag.fmt("field '" + field + "' needs at least " + minBytes + " byte(s)",
                    path + "." + field, v));
            return null;
        }
        return h.toLowerCase();
    }

    private static Direction parseDirection(JsonNode n, String path, List<Diagnostic> errs) {
        String v = requireText(n, "direction", path, errs);
        if (v == null) {
            return null;
        }
        Direction d = Direction.fromRaw(v);
        if (d == null) {
            errs.add(Diag.sem("direction must be RX or TX, got '" + v + "'",
                    path + ".direction", v));
        }
        return d;
    }

    /**
     * Quantities keep the original representation. {@code node} may give either a
     * string ({@code "12.5"}) or an object {@code {raw, unit}}; a value we cannot
     * normalize is preserved with a WARNING diagnostic rather than dropped.
     */
    private static Quant parseQuant(JsonNode parent, String field, String basis, String path,
                                    List<Diagnostic> diags, boolean required) {
        JsonNode v = parent.get(field);
        if (v == null || v.isNull()) {
            if (required) {
                diags.add(Diag.fmt("missing field '" + field + "'", path + "." + field, null));
            }
            return null;
        }
        String raw;
        String unit;
        if (v.isObject()) {
            raw = optionalText(v, "raw", null);
            unit = optionalText(v, "unit", "");
            if (raw == null) {
                diags.add(Diag.fmt("quantity object needs 'raw'", path + "." + field, null));
                return null;
            }
        } else if (v.isTextual()) {
            raw = v.asText();
            unit = "";
        } else if (v.isNumber()) {
            raw = String.valueOf(v.numberValue());
            unit = "";
        } else {
            diags.add(Diag.fmt("quantity must be string, number or object",
                    path + "." + field, String.valueOf(v)));
            return null;
        }
        Double normalized = null;
        try {
            normalized = Double.parseDouble(raw.trim());
        } catch (NumberFormatException ignored) {
            diags.add(Diagnostic.warning("UNNORMALIZABLE_QUANTITY",
                    "value '" + raw + "' kept at " + path + " but could not be normalized",
                    path + "." + field, raw));
        }
        return new Quant(raw, unit, normalized, canonicalUnit(unit), basis);
    }

    private static String canonicalUnit(String unit) {
        if (unit == null) {
            return "";
        }
        return unit.trim().toLowerCase();
    }

    private static String truncate(String s, int n) {
        if (s == null) {
            return null;
        }
        return s.length() <= n ? s : s.substring(0, n) + "…";
    }

    /** Small helper so diagnostic construction reads uniformly above. */
    static final class Diag {
        static org.quiccourt.domain.DiagClass FMT = org.quiccourt.domain.DiagClass.FORMAT_CORRUPT;
        static org.quiccourt.domain.DiagClass SEM = org.quiccourt.domain.DiagClass.SEMANTIC_NO_SOLUTION;

        static Diagnostic fmt(String msg, String location, String evidence) {
            return Diagnostic.error(FMT, "FORMAT", msg, location, evidence, List.of());
        }

        static Diagnostic sem(String msg, String location, String evidence) {
            return Diagnostic.error(SEM, "SEMANTIC", msg, location, evidence, List.of());
        }
    }
}
