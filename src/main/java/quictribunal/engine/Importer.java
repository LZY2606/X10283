package quictribunal.engine;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import quictribunal.model.Domain;
import quictribunal.json.Json;
import quictribunal.model.Ids;
/**
 * Validates a capture bundle before any of it is allowed to touch storage. Validation is
 * all-or-nothing: a single failure returns diagnostics with positions and zero materials are
 * persisted. The three failure classes (format corrupt / semantic unsolvable / budget exhausted)
 * are kept distinct.
 */
public final class Importer {
    private Importer() {}

    public static final class Capture {
        public String projectId = "";
        public String timeBase = "capture-relative ns (t=0 is capture start)";
        public final List<Domain.PathInfo> paths = new ArrayList<>();
        public final List<Domain.KeyGen> keyGens = new ArrayList<>();
        public final List<Domain.CidEvent> cidEvents = new ArrayList<>();
        public final List<Domain.Datagram> datagrams = new ArrayList<>();
        public final List<Domain.HpCandidate> hpCandidates = new ArrayList<>();
        public final List<Domain.Packet> packets = new ArrayList<>();
        public final List<Domain.RuleParams> paramHistory = new ArrayList<>();

        public Map<String, Object> toMap() {
            Map<String, Object> m = new java.util.LinkedHashMap<>();
            m.put("projectId", projectId);
            m.put("timeBase", timeBase);
            m.put("paths", paths.stream().map(p -> {
                Map<String, Object> x = new java.util.LinkedHashMap<>();
                x.put("id", p.id());
                x.put("fourTuple", p.fourTuple());
                return x;
            }).toList());
            m.put("keyGens", keyGens.stream().map(g -> {
                Map<String, Object> x = new java.util.LinkedHashMap<>();
                x.put("id", g.id());
                x.put("role", g.role().name());
                x.put("generation", g.generation());
                x.put("validFromNs", g.validFromNs());
                x.put("validUntilNs", g.validUntilNs());
                x.put("secretLabel", g.secretLabel());
                return x;
            }).toList());
            m.put("cidEvents", cidEvents.stream().map(c -> {
                Map<String, Object> x = new java.util.LinkedHashMap<>();
                x.put("id", c.id());
                x.put("seq", c.seq());
                x.put("cidHex", c.cidHex());
                x.put("issuedNs", c.issuedNs());
                x.put("retiredNs", c.retiredNs());
                x.put("issuedOnPathId", c.issuedOnPathId());
                return x;
            }).toList());
            m.put("datagrams", datagrams.stream().map(d -> {
                Map<String, Object> x = new java.util.LinkedHashMap<>();
                x.put("id", d.id());
                x.put("tNs", d.tNs());
                x.put("dir", d.dir().name());
                x.put("pathId", d.pathId());
                x.put("bytesHex", d.bytesHex());
                return x;
            }).toList());
            m.put("hpCandidates", hpCandidates.stream().map(h -> {
                Map<String, Object> x = new java.util.LinkedHashMap<>();
                x.put("id", h.id());
                x.put("packetId", h.packetId());
                x.put("maskHex", h.maskHex());
                x.put("applied", h.applied());
                x.put("note", h.note());
                return x;
            }).toList());
            m.put("packets", packets.stream().map(pk -> {
                Map<String, Object> x = new java.util.LinkedHashMap<>();
                x.put("id", pk.id());
                x.put("datagramId", pk.datagramId());
                x.put("offset", pk.offset());
                x.put("space", pk.space().name());
                x.put("longHeader", pk.longHeader());
                x.put("version", pk.version());
                x.put("dcidHex", pk.dcidHex());
                x.put("scidHex", pk.scidHex());
                x.put("keyGeneration", pk.keyGeneration());
                x.put("keyPhaseBit", pk.keyPhaseBit());
                x.put("truncatedPn", pk.truncatedPn());
                x.put("pnLen", pk.pnLenBytes());
                x.put("decryptableGens", pk.decryptableGens());
                x.put("ackFrameHex", pk.ackFrameHex());
                x.put("rawHeaderHex", pk.rawHeaderHex());
                return x;
            }).toList());
            return m;
        }
    }

    public static final class Result {
        public final Capture capture;
        public final List<Domain.Diagnostic> diagnostics;

        Result(Capture capture, List<Domain.Diagnostic> diagnostics) {
            this.capture = capture;
            this.diagnostics = List.copyOf(diagnostics);
        }

        public boolean ok() {
            return diagnostics.stream().noneMatch(d -> d.kind() != Domain.Outcome.OK) && capture != null;
        }
    }

    // ---------------------------------------------------------------- parse

    public static Result parseCapture(String jsonText) {
        List<Domain.Diagnostic> diags = new ArrayList<>();
        Object root;
        try {
            root = Json.parse(jsonText);
        } catch (Json.JsonException je) {
            diags.add(new Domain.Diagnostic("JSON_MALFORMED",
                    Domain.Outcome.FORMAT_CORRUPT, "$", je.position, 1, je.getMessage()));
            return new Result(null, diags);
        }
        if (!(root instanceof Map<?, ?>)) {
            diags.add(Domain.Diagnostic.format("JSON_NOT_OBJECT", "$", 0,
                    "capture bundle root must be a JSON object"));
            return new Result(null, diags);
        }
        @SuppressWarnings("unchecked")
        Map<String, Object> m = (Map<String, Object>) root;
        String fv = str(m.get("formatVersion"));
        if (fv == null) {
            diags.add(Domain.Diagnostic.format("FORMAT_VERSION_MISSING", "$.formatVersion", null,
                    "formatVersion is required"));
        } else if (!fv.equals("quic-capture/1")) {
            diags.add(Domain.Diagnostic.format("FORMAT_VERSION_UNKNOWN", "$.formatVersion", null,
                    "unsupported formatVersion '" + fv + "'"));
        }
        Capture cap = new Capture();
        cap.projectId = str(m.get("projectId"));
        if (cap.projectId == null || cap.projectId.isBlank()) {
            diags.add(Domain.Diagnostic.format("PROJECT_ID_MISSING", "$.projectId", null,
                    "projectId is required"));
        }
        if (m.get("timeBase") != null) cap.timeBase = String.valueOf(m.get("timeBase"));

        Set<String> datagramIds = new HashSet<>();
        Set<String> packetIds = new HashSet<>();
        readPaths(cap, m, diags);
        readKeyGens(cap, m, diags);
        readCidEvents(cap, m, diags);
        readDatagrams(cap, m, diags, datagramIds);
        readHpCandidates(cap, m, diags);
        readPackets(cap, m, diags, datagramIds, packetIds);
        return new Result(cap, diags);
    }

    private static String str(Object v) {
        return v == null ? null : String.valueOf(v);
    }

    private static void readPaths(Capture cap, Map<String, Object> m,
                                  List<Domain.Diagnostic> diags) {
        for (MapObj obj : list(m, "paths", diags)) {
            String id = required(obj, "id", diags);
            String four = required(obj, "fourTuple", diags);
            if (id != null && four != null) {
                cap.paths.add(new Domain.PathInfo(id, four));
            }
        }
    }

    private static void readKeyGens(Capture cap, Map<String, Object> m,
                                    List<Domain.Diagnostic> diags) {
        for (MapObj obj : list(m, "keyGens", diags)) {
            String id = required(obj, "id", diags);
            Domain.KeyRole role = enumOr(Domain.KeyRole.class, obj.m.get("role"),
                    obj.path + ".role", diags);
            Long gen = longOr(obj, "generation", diags);
            Long from = longOr(obj, "validFromNs", diags);
            Long until = obj.m.get("validUntilNs") == null ? null
                    : numeric(obj.m.get("validUntilNs"), obj.path + ".validUntilNs", diags);
            String label = required(obj, "secretLabel", diags);
            if (id != null && role != null && gen != null && from != null && label != null) {
                cap.keyGens.add(new Domain.KeyGen(id, role, gen, from, until, label));
            }
        }
    }

    private static void readCidEvents(Capture cap, Map<String, Object> m,
                                      List<Domain.Diagnostic> diags) {
        for (MapObj obj : list(m, "cidEvents", diags)) {
            String id = required(obj, "id", diags);
            Long seq = longOr(obj, "seq", diags);
            String cid = hexOr(obj, "cidHex", diags);
            Long issued = longOr(obj, "issuedNs", diags);
            Long retired = obj.m.get("retiredNs") == null ? null
                    : numeric(obj.m.get("retiredNs"), obj.path + ".retiredNs", diags);
            String pathId = obj.m.get("issuedOnPathId") == null ? null
                    : String.valueOf(obj.m.get("issuedOnPathId"));
            if (id != null && seq != null && cid != null && issued != null) {
                cap.cidEvents.add(new Domain.CidEvent(id, seq, cid, issued, retired, pathId));
            }
        }
    }

    private static void readDatagrams(Capture cap, Map<String, Object> m,
                                      List<Domain.Diagnostic> diags, Set<String> ids) {
        for (MapObj obj : list(m, "datagrams", diags)) {
            String id = required(obj, "id", diags);
            Long t = longOr(obj, "tNs", diags);
            Domain.Direction dir = enumOr(Domain.Direction.class, obj.m.get("dir"),
                    obj.path + ".dir", diags);
            String pathId = required(obj, "pathId", diags);
            String bytes = hexOr(obj, "bytesHex", diags);
            if (id != null && !ids.add(id)) {
                diags.add(Domain.Diagnostic.format("DUP_ID", obj.path + ".id", null,
                        "duplicate datagram id '" + id + "'"));
            }
            if (id != null && t != null && dir != null && pathId != null && bytes != null) {
                cap.datagrams.add(new Domain.Datagram(id, t, dir, pathId, bytes));
            }
        }
    }

    private static void readHpCandidates(Capture cap, Map<String, Object> m,
                                         List<Domain.Diagnostic> diags) {
        for (MapObj obj : list(m, "hpCandidates", diags)) {
            String id = required(obj, "id", diags);
            String packetId = required(obj, "packetId", diags);
            String mask = hexOr(obj, "maskHex", diags);
            boolean applied = Boolean.TRUE.equals(obj.m.get("applied"));
            String note = obj.m.get("note") == null ? "" : String.valueOf(obj.m.get("note"));
            if (id != null && packetId != null && mask != null) {
                cap.hpCandidates.add(new Domain.HpCandidate(id, packetId, mask, applied, note));
            }
        }
    }

    private static void readPackets(Capture cap, Map<String, Object> m,
                                    List<Domain.Diagnostic> diags,
                                    Set<String> datagramIds, Set<String> packetIds) {
        for (MapObj obj : list(m, "packets", diags)) {
            String id = required(obj, "id", diags);
            String dgId = required(obj, "datagramId", diags);
            Long offset = longOr(obj, "offset", diags);
            Domain.PnSpace space = enumOr(Domain.PnSpace.class, obj.m.get("space"),
                    obj.path + ".space", diags);
            boolean longHeader = Boolean.TRUE.equals(obj.m.get("longHeader"));
            long version = obj.m.get("version") == null ? 0L
                    : numeric(obj.m.get("version"), obj.path + ".version", diags) == null ? 0L
                    : numeric(obj.m.get("version"), obj.path + ".version", diags);
            String dcid = nullableHex(obj, "dcidHex", diags);
            String scid = nullableHex(obj, "scidHex", diags);
            Long keyGen = longOr(obj, "keyGeneration", diags);
            Integer kpb = obj.m.get("keyPhaseBit") == null ? null
                    : (int) (long) numeric(obj.m.get("keyPhaseBit"), obj.path + ".keyPhaseBit", diags);
            Long truncated = longOr(obj, "truncatedPn", diags);
            Long pnLen = longOr(obj, "pnLen", diags);
            List<Long> gens = new ArrayList<>();
            Object raw = obj.m.get("decryptableGens");
            if (raw != null) {
                if (!(raw instanceof List<?>)) {
                    diags.add(Domain.Diagnostic.format("FIELD_NOT_ARRAY",
                            obj.path + ".decryptableGens", null, "expected array of integers"));
                } else {
                    int i = 0;
                    for (Object g : (List<?>) raw) {
                        Long v = numeric(g, obj.path + ".decryptableGens[" + i + "]", diags);
                        if (v != null) gens.add(v);
                        i++;
                    }
                }
            }
            String ackHex = nullableHex(obj, "ackFrameHex", diags);
            String headerHex = hexOr(obj, "rawHeaderHex", diags);
            if (id != null && !packetIds.add(id)) {
                diags.add(Domain.Diagnostic.format("DUP_ID", obj.path + ".id", null,
                        "duplicate packet id '" + id + "'"));
            }
            if (dgId != null && !datagramIds.contains(dgId)) {
                diags.add(Domain.Diagnostic.semantic("DATAGRAM_MISSING",
                        obj.path + ".datagramId",
                        "packet '" + id + "' references unknown datagram '" + dgId + "'"));
            }
            if (pnLen != null && (pnLen < 1 || pnLen > 4)) {
                diags.add(Domain.Diagnostic.semantic("PN_LEN_BAD",
                        obj.path + ".pnLen",
                        "truncated packet number length must be 1..4 bytes, got " + pnLen));
            }
            if (kpb != null && (kpb < 0 || kpb > 1)) {
                diags.add(Domain.Diagnostic.semantic("KEY_PHASE_BIT_BAD",
                        obj.path + ".keyPhaseBit", "key phase bit must be 0 or 1"));
            }
            if (ackHex != null) {
                Engine.AckRead ar = Engine.parseAckFrame(Engine.hex(ackHex),
                        obj.path + ".ackFrameHex");
                diags.addAll(ar.errors());
            }
            if (id != null && dgId != null && offset != null && space != null
                    && keyGen != null && truncated != null && pnLen != null
                    && headerHex != null) {
                Domain.Datagram dg = cap.datagrams.stream()
                        .filter(d -> d.id().equals(dgId)).findFirst().orElse(null);
                Domain.Packet pk = new Domain.Packet(id, dgId, offset.intValue(), space,
                        longHeader, version, dcid, scid, keyGen, kpb, truncated,
                        pnLen.intValue(), List.copyOf(gens), ackHex, headerHex);
                cap.packets.add(pk);
                if (dg != null) checkRawInsideDatagram(pk, dg, obj.path, diags);
            }
        }
    }

    /** The claimed raw header bytes must actually exist at the claimed offset in the datagram. */
    private static void checkRawInsideDatagram(Domain.Packet pk, Domain.Datagram dg,
                                               String path, List<Domain.Diagnostic> diags) {
        byte[] dgBytes;
        byte[] hdr;
        try {
            dgBytes = Engine.hex(dg.bytesHex());
            hdr = Engine.hex(pk.rawHeaderHex());
        } catch (IllegalArgumentException bad) {
            return; // hex already reported
        }
        if (pk.offset() < 0 || pk.offset() + hdr.length > dgBytes.length) {
            diags.add(new Domain.Diagnostic("HEADER_OUT_OF_DATAGRAM",
                    Domain.Outcome.FORMAT_CORRUPT, path + ".offset", pk.offset(), hdr.length,
                    "rawHeaderHex (" + hdr.length + " bytes) does not fit datagram of "
                            + dgBytes.length + " bytes at offset " + pk.offset()));
            return;
        }
        for (int i = 0; i < hdr.length; i++) {
            if (hdr[i] != dgBytes[pk.offset() + i]) {
                diags.add(new Domain.Diagnostic("HEADER_BYTES_MISMATCH",
                        Domain.Outcome.FORMAT_CORRUPT, path + ".rawHeaderHex",
                        pk.offset() + i, 1,
                        "rawHeaderHex byte " + i + " disagrees with datagram bytes"));
                return;
            }
        }
        if (pk.ackFrameHex() != null) {
            int pnEnd = pk.offset() + hdr.length;
            int ackLen = Engine.hex(pk.ackFrameHex()).length;
            if (pnEnd + ackLen > dgBytes.length) {
                diags.add(new Domain.Diagnostic("ACK_OUT_OF_DATAGRAM",
                        Domain.Outcome.FORMAT_CORRUPT, path + ".ackFrameHex", pnEnd, ackLen,
                        "ACK frame runs past end of datagram"));
            }
        }
    }

    // ---------------------------------------------------------------- helpers

    private record MapObj(Map<String, Object> m, String path) {}

    @SuppressWarnings("unchecked")
    private static List<MapObj> list(Map<String, Object> root, String key,
                                     List<Domain.Diagnostic> diags) {
        Object v = root.get(key);
        if (v == null) return List.of();
        if (!(v instanceof List<?> raw)) {
            diags.add(Domain.Diagnostic.format("FIELD_NOT_ARRAY", "$." + key, null,
                    "'" + key + "' must be an array"));
            return List.of();
        }
        List<MapObj> out = new ArrayList<>();
        int i = 0;
        for (Object item : raw) {
            if (!(item instanceof Map<?, ?>)) {
                diags.add(Domain.Diagnostic.format("ELEMENT_NOT_OBJECT",
                        "$." + key + "[" + i + "]", null, "each element must be an object"));
            } else {
                out.add(new MapObj((Map<String, Object>) item, "$." + key + "[" + i + "]"));
            }
            i++;
        }
        return out;
    }

    private static String required(MapObj obj, String key, List<Domain.Diagnostic> diags) {
        Object v = obj.m.get(key);
        if (v == null || String.valueOf(v).isBlank()) {
            diags.add(Domain.Diagnostic.format("FIELD_REQUIRED", obj.path + "." + key, null,
                    "'" + key + "' is required"));
            return null;
        }
        return String.valueOf(v);
    }

    private static Long numeric(Object v, String path, List<Domain.Diagnostic> diags) {
        if (v instanceof Number n) return n.longValue();
        diags.add(Domain.Diagnostic.format("FIELD_NOT_INTEGER", path, null,
                "expected integer, got " + (v == null ? "null" : v.getClass().getSimpleName())));
        return null;
    }

    private static Long longOr(MapObj obj, String key, List<Domain.Diagnostic> diags) {
        Object v = obj.m.get(key);
        if (v == null) {
            diags.add(Domain.Diagnostic.format("FIELD_REQUIRED", obj.path + "." + key, null,
                    "'" + key + "' is required"));
            return null;
        }
        return numeric(v, obj.path + "." + key, diags);
    }

    private static <T extends Enum<T>> T enumOr(Class<T> type, Object v, String path,
                                                List<Domain.Diagnostic> diags) {
        if (v == null) {
            diags.add(Domain.Diagnostic.format("FIELD_REQUIRED", path, null, "required enum"));
            return null;
        }
        try {
            return Enum.valueOf(type, String.valueOf(v));
        } catch (IllegalArgumentException bad) {
            diags.add(Domain.Diagnostic.format("ENUM_UNKNOWN", path, null,
                    "unknown value '" + v + "' for " + type.getSimpleName()));
            return null;
        }
    }

    private static String hexOr(MapObj obj, String key, List<Domain.Diagnostic> diags) {
        String v = required(obj, key, diags);
        if (v == null) return null;
        return validateHex(v, obj.path + "." + key, diags);
    }

    private static String nullableHex(MapObj obj, String key, List<Domain.Diagnostic> diags) {
        Object v = obj.m.get(key);
        if (v == null) return null;
        return validateHex(String.valueOf(v), obj.path + "." + key, diags);
    }

    private static String validateHex(String v, String path, List<Domain.Diagnostic> diags) {
        if (!v.matches("[0-9a-fA-F]*") || (v.length() % 2) != 0) {
            diags.add(Domain.Diagnostic.format("HEX_INVALID", path, 0,
                    "value must be even-length hexadecimal"));
            return null;
        }
        return v.toLowerCase();
    }
}
