package quiccourt.xfer;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import quiccourt.core.Diagnostic;
import quiccourt.core.Digests;
import quiccourt.core.Status;
import quiccourt.model.Decision;
import quiccourt.model.Material;
import quiccourt.model.MaterialKind;
import quiccourt.store.Store;

import java.io.IOException;
import java.nio.file.*;
import java.util.ArrayList;
import java.util.List;

/** Case export/import. Identity, order and provenance survive the round trip.
 *  Export is atomic (temp file + move); import is one transaction, so a
 *  half-written or corrupt file can never leave partial state behind. */
public final class Transfer {
    public static final String FORMAT = "quic-pn-court-export";
    public static final int FORMAT_VERSION = 1;

    private final Store store;
    private final ObjectMapper om;

    public Transfer(Store store) { this.store = store; this.om = store.mapper(); }

    public ObjectNode exportCase(String caseId) {
        Store.CaseRow c = store.caseRow(caseId);
        ObjectNode root = om.createObjectNode();
        root.put("format", FORMAT);
        root.put("format_version", FORMAT_VERSION);
        ObjectNode co = root.putObject("case");
        co.put("id", c.id()); co.put("name", c.name());
        co.put("time_base", c.timeBase()); co.put("description", c.description());
        ArrayNode branches = root.putArray("branches");
        store.branches(caseId).forEach((name, bi) -> {
            ObjectNode b = branches.addObject();
            b.put("name", bi.name());
            if (bi.parent() != null) b.put("parent", bi.parent());
            if (bi.forkSeq() != null) b.put("fork_seq", bi.forkSeq());
        });
        ArrayNode events = root.putArray("events");
        for (Store.EventRow e : store.allEvents(caseId)) {
            ObjectNode n = events.addObject();
            n.put("id", e.id()); n.put("branch", e.branch()); n.put("seq", e.seq());
            n.put("kind", e.kind()); n.set("payload", e.payload());
            if (e.inputDigest() != null) n.put("input_digest", e.inputDigest());
        }
        ArrayNode mats = root.putArray("materials");
        for (Material m : store.allMaterials(caseId)) {
            ObjectNode n = mats.addObject();
            n.put("id", m.id()); n.put("branch", m.branch()); n.put("seq", m.seq());
            n.put("kind", m.kind().name()); n.set("raw", m.raw());
            n.put("digest", m.digest()); n.put("introduced_by_event", m.introducedByEvent());
        }
        ArrayNode decs = root.putArray("decisions");
        for (Decision d : store.allDecisions(caseId)) {
            ObjectNode n = decs.addObject();
            n.put("id", d.id()); n.put("branch", d.branch()); n.put("seq", d.seq());
            n.put("kind", d.kind()); n.put("target_id", d.targetId());
            n.set("payload", d.payload());
            if (d.supersedes() != null) n.put("supersedes", d.supersedes());
            n.put("introduced_by_event", d.introducedByEvent());
        }
        ArrayNode ders = root.putArray("derived");
        for (String branch : store.branches(caseId).keySet()) {
            for (Store.DerivedRow r : store.derivedFor(caseId, branch)) {
                ObjectNode n = ders.addObject();
                n.put("id", r.id()); n.put("branch", r.branch()); n.put("view", r.view());
                n.put("input_digest", r.inputDigest()); n.put("param_version", r.paramVersion());
                n.put("parents", r.parents()); n.put("status", r.status());
                n.set("payload", r.payload()); n.set("diagnostics", r.diagnostics());
                n.put("seq", r.seq());
            }
        }
        return root;
    }

    /** Atomic export: half-written targets are impossible. */
    public Path exportToFile(String caseId, Path target) throws IOException {
        ObjectNode doc = exportCase(caseId);
        byte[] bytes = om.writerWithDefaultPrettyPrinter().writeValueAsBytes(doc);
        Path tmp = target.resolveSibling(target.getFileName() + ".tmp");
        Files.write(tmp, bytes, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
        Files.move(tmp, target, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        return target;
    }

    public record ImportResult(Status status, String caseId, List<Diagnostic> diagnostics,
                               int materials, int events, int decisions, int derived) {
        public boolean ok() { return status == Status.OK; }
    }

    public ImportResult importCase(JsonNode doc) {
        List<Diagnostic> diags = new ArrayList<>();
        if (doc == null || !doc.isObject())
            return new ImportResult(Status.FORMAT_CORRUPT, null,
                    List.of(new Diagnostic("xfer#/", "FORMAT_CORRUPT", "document is not a JSON object")), 0, 0, 0, 0);
        JsonNode fmt = doc.get("format");
        if (fmt == null || !FORMAT.equals(fmt.asText()))
            return new ImportResult(Status.FORMAT_CORRUPT, null,
                    List.of(new Diagnostic("xfer#/format", "FORMAT_CORRUPT", "not a " + FORMAT + " document")), 0, 0, 0, 0);
        JsonNode caseNode = doc.get("case");
        if (caseNode == null || !caseNode.hasNonNull("id"))
            return new ImportResult(Status.FORMAT_CORRUPT, null,
                    List.of(new Diagnostic("xfer#/case/id", "MISSING_FIELD", "case id required")), 0, 0, 0, 0);
        String caseId = caseNode.get("id").asText();

        // Validate everything BEFORE touching the database: corrupt input never
        // produces partial state.
        JsonNode mats = doc.get("materials");
        if (mats == null || !mats.isArray())
            return new ImportResult(Status.FORMAT_CORRUPT, caseId,
                    List.of(new Diagnostic("xfer#/materials", "FORMAT_CORRUPT", "materials array required")), 0, 0, 0, 0);
        for (int i = 0; i < mats.size(); i++) {
            JsonNode m = mats.get(i);
            String pos = "xfer#/materials/" + i;
            for (String f : new String[]{"id", "branch", "seq", "kind", "raw", "digest", "introduced_by_event"}) {
                if (!m.hasNonNull(f)) diags.add(new Diagnostic(pos + "/" + f, "MISSING_FIELD", "required for identity-preserving import"));
            }
            if (!diags.isEmpty()) continue;
            String recomputed = Digests.sha256(m.get("raw").toString());
            if (!recomputed.equals(m.get("digest").asText()))
                diags.add(new Diagnostic(pos + "/digest", "FORMAT_CORRUPT",
                        "material digest mismatch: evidence bytes were altered or truncated"));
            try { MaterialKind.valueOf(m.get("kind").asText()); }
            catch (IllegalArgumentException e) {
                diags.add(new Diagnostic(pos + "/kind", "FORMAT_CORRUPT", "unknown material kind"));
            }
        }
        JsonNode events = doc.get("events");
        if (events == null || !events.isArray())
            diags.add(new Diagnostic("xfer#/events", "FORMAT_CORRUPT", "events array required"));
        if (!diags.isEmpty())
            return new ImportResult(Status.FORMAT_CORRUPT, caseId, diags, 0, 0, 0, 0);

        store.begin();
        try {
            store.putCase(caseId, caseNode.path("name").asText(caseId),
                    caseNode.path("time_base").asText("us-since-case-epoch"),
                    caseNode.path("description").asText(""));
            JsonNode branches = doc.get("branches");
            if (branches != null) {
                for (JsonNode b : branches) {
                    store.ensureBranch(caseId, b.get("name").asText(),
                            b.hasNonNull("parent") ? b.get("parent").asText() : null,
                            b.hasNonNull("fork_seq") ? b.get("fork_seq").asLong() : null);
                }
            }
            int evCount = 0;
            for (JsonNode e : events) {
                store.appendEvent(e.get("id").asText(), caseId, e.get("branch").asText(),
                        e.get("seq").asLong(), e.get("kind").asText(), e.get("payload"),
                        e.hasNonNull("input_digest") ? e.get("input_digest").asText() : null);
                store.raiseCounter("ev", e.get("id").asText());
                evCount++;
            }
            int matCount = 0;
            for (JsonNode m : mats) {
                store.appendMaterial(new Material(m.get("id").asText(), caseId, m.get("branch").asText(),
                        m.get("seq").asLong(), MaterialKind.valueOf(m.get("kind").asText()),
                        m.get("raw"), m.get("digest").asText(), m.get("introduced_by_event").asText()));
                store.raiseCounter("mat", m.get("id").asText());
                matCount++;
            }
            int decCount = 0;
            JsonNode decs = doc.get("decisions");
            if (decs != null) {
                for (JsonNode d : decs) {
                    store.appendDecision(new Decision(d.get("id").asText(), caseId, d.get("branch").asText(),
                            d.get("seq").asLong(), d.get("kind").asText(), d.get("target_id").asText(),
                            d.get("payload"), d.hasNonNull("supersedes") ? d.get("supersedes").asText() : null,
                            d.get("introduced_by_event").asText()));
                    store.raiseCounter("dec", d.get("id").asText());
                    decCount++;
                }
            }
            int derCount = 0;
            JsonNode ders = doc.get("derived");
            if (ders != null) {
                for (JsonNode r : ders) {
                    List<String> parents = r.get("parents").asText().isEmpty()
                            ? List.of() : List.of(r.get("parents").asText().split(","));
                    store.saveDerived(r.get("id").asText(), caseId, r.get("branch").asText(),
                            r.get("view").asText(), r.get("input_digest").asText(),
                            r.get("param_version").asText(), parents, r.get("status").asText(),
                            r.get("payload"), r.get("diagnostics"), r.get("seq").asLong());
                    derCount++;
                }
            }
            store.commit();
            return new ImportResult(Status.OK, caseId, List.of(), matCount, evCount, decCount, derCount);
        } catch (RuntimeException ex) {
            store.rollback();
            return new ImportResult(Status.FORMAT_CORRUPT, caseId,
                    List.of(new Diagnostic("xfer#/", "FORMAT_CORRUPT",
                            "import rolled back, database unchanged: " + ex.getMessage())), 0, 0, 0, 0);
        }
    }

    public ImportResult importFile(Path file) {
        final JsonNode doc;
        try {
            doc = om.readTree(Files.readAllBytes(file));
        } catch (Exception e) {
            return new ImportResult(Status.FORMAT_CORRUPT, null,
                    List.of(new Diagnostic("file:" + file.getFileName(), "FORMAT_CORRUPT",
                            "unreadable or truncated JSON: " + e.getMessage())), 0, 0, 0, 0);
        }
        return importCase(doc);
    }
}
