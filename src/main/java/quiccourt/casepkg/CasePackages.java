package quiccourt.casepkg;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import quiccourt.core.Digests;
import quiccourt.model.Decision;
import quiccourt.model.Material;
import quiccourt.model.MaterialKind;
import quiccourt.store.Store;

import java.io.InputStream;

/** Loads the bundled offline case package "QUIC 包号庭" and replays its event
 *  script into the store. Ids in the package are stable identities: re-loading,
 *  exporting and re-importing preserve them exactly. */
public final class CasePackages {
    public static final String BUNDLED = "/casepkg/quic-pn-court/case.json";
    public static final String CASE_ID = "quic-pn-court-001";

    private CasePackages() {}

    public static boolean loadBundled(Store store) {
        if (store.caseRow(CASE_ID) != null) return false;
        ObjectMapper om = store.mapper();
        JsonNode doc;
        try (InputStream in = CasePackages.class.getResourceAsStream(BUNDLED)) {
            if (in == null) throw new IllegalStateException("missing resource " + BUNDLED);
            doc = om.readTree(in);
        } catch (Exception e) {
            throw new RuntimeException("cannot load bundled case package", e);
        }
        replay(store, doc);
        return true;
    }

    /** Replay a case-package script: branches, then ordered steps of
     *  event + materials + decisions. */
    public static void replay(Store store, JsonNode doc) {
        ObjectMapper om = store.mapper();
        JsonNode c = doc.get("case");
        String caseId = c.get("id").asText();
        store.putCase(caseId, c.get("name").asText(),
                c.get("time_base").asText(), c.path("description").asText(""));

        JsonNode branches = doc.get("branches");
        if (branches != null) {
            for (JsonNode b : branches) {
                store.ensureBranch(caseId, b.get("name").asText(),
                        b.hasNonNull("parent") ? b.get("parent").asText() : null,
                        b.hasNonNull("fork_seq") ? b.get("fork_seq").asLong() : null);
            }
        }

        for (JsonNode step : doc.get("steps")) {
            JsonNode ev = step.get("event");
            String evId = ev.get("id").asText();
            String branch = ev.get("branch").asText();
            long evSeq = store.nextSeq(caseId, branch, "events");
            store.appendEvent(evId, caseId, branch, evSeq, ev.get("kind").asText(),
                    ev.get("payload"), ev.hasNonNull("input_digest") ? ev.get("input_digest").asText() : null);
            store.raiseCounter("ev", evId);

            JsonNode mats = step.get("materials");
            if (mats != null) {
                for (JsonNode m : mats) {
                    String id = m.get("id").asText();
                    JsonNode raw = m.get("raw");
                    long seq = store.nextSeq(caseId, branch, "materials");
                    store.appendMaterial(new Material(id, caseId, branch, seq,
                            MaterialKind.valueOf(m.get("kind").asText()), raw,
                            Digests.sha256(raw.toString()), evId));
                    store.raiseCounter("mat", id);
                }
            }
            JsonNode decs = step.get("decisions");
            if (decs != null) {
                for (JsonNode d : decs) {
                    String id = d.get("id").asText();
                    long seq = store.nextSeq(caseId, branch, "decisions");
                    store.appendDecision(new Decision(id, caseId, branch, seq,
                            d.get("kind").asText(), d.get("target_id").asText(), d.get("payload"),
                            d.hasNonNull("supersedes") ? d.get("supersedes").asText() : null, evId));
                    store.raiseCounter("dec", id);
                }
            }
        }
    }
}
