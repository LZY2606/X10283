package quiccourt.engine;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import quiccourt.core.Budget;
import quiccourt.core.Diagnostic;
import quiccourt.core.Digests;
import quiccourt.core.Status;
import quiccourt.model.Decision;
import quiccourt.model.M;
import quiccourt.model.Material;
import quiccourt.model.MaterialKind;
import quiccourt.store.Store;

import java.util.*;

/** Computes the five review views (pn_spaces, ack_ranges, key_phase, cid_lineage,
 *  timeline) from immutable materials plus mutable decisions at an event horizon.
 *  Every result records input digest, parameter version and parent dependencies;
 *  incomplete input yields positioned diagnostics, never silent defaults. */
public final class Pipeline {
    public static final List<String> VIEWS = List.of("pn_spaces", "ack_ranges", "key_phase", "cid_lineage", "timeline");
    public static final long DEFAULT_BUDGET = 100_000;

    private final Store store;
    private final ObjectMapper om;

    public Pipeline(Store store) {
        this.store = store;
        this.om = store.mapper();
    }

    public record ViewResult(String id, String view, Status status, JsonNode payload,
                             List<Diagnostic> diagnostics, List<String> parents,
                             String inputDigest, String paramVersion, boolean fromCache) {}

    /** Effective parameters at the horizon, from PARAM_ADJUST decisions. */
    public record Params(int confirmPackets, int gracePackets, long budget, String version) {}

    public Params paramsAt(String caseId, String branch, Long atSeq) {
        int confirm = 2, grace = 3;
        long budget = DEFAULT_BUDGET;
        String version = "pv-0";
        for (Decision d : store.decisionsVisible(caseId, branch, atSeq)) {
            if (!"PARAM_ADJUST".equals(d.kind())) continue;
            JsonNode p = d.payload();
            if (p.has("confirm_packets")) confirm = p.get("confirm_packets").asInt();
            if (p.has("grace_packets")) grace = p.get("grace_packets").asInt();
            if (p.has("budget")) budget = p.get("budget").asLong();
            if (p.has("param_version")) version = p.get("param_version").asText();
        }
        return new Params(confirm, grace, budget, version);
    }

    /** Decisions in force: superseded ones drop out; conflicting live ones are reported. */
    public record DecisionState(Map<String, List<Decision>> liveByTarget, List<Diagnostic> conflicts) {}

    public DecisionState decisionsAt(String caseId, String branch, Long atSeq) {
        List<Decision> visible = store.decisionsVisible(caseId, branch, atSeq);
        Set<String> superseded = new HashSet<>();
        for (Decision d : visible) if (d.supersedes() != null) superseded.add(d.supersedes());
        Map<String, List<Decision>> live = new LinkedHashMap<>();
        for (Decision d : visible) {
            if (superseded.contains(d.id()) || "PARAM_ADJUST".equals(d.kind())) continue;
            live.computeIfAbsent(d.targetId(), k -> new ArrayList<>()).add(d);
        }
        List<Diagnostic> conflicts = new ArrayList<>();
        for (var e : live.entrySet()) {
            boolean accept = e.getValue().stream().anyMatch(d -> "ACCEPT".equals(d.kind()));
            boolean reject = e.getValue().stream().anyMatch(d -> "REJECT".equals(d.kind()));
            if (accept && reject) {
                List<String> ids = e.getValue().stream().map(Decision::id).sorted().toList();
                conflicts.add(new Diagnostic("decision:" + String.join(",", ids), "CONFLICTING_DECISIONS",
                        "accept and reject both live on target " + e.getKey() + "; all legal candidates retained"));
            }
        }
        return new DecisionState(live, conflicts);
    }

    /** Material kinds each view depends on; everything else is invisible to that view. */
    public static final Map<String, Set<MaterialKind>> DEPENDENCIES = Map.of(
            "pn_spaces", EnumSet.of(MaterialKind.DATAGRAM, MaterialKind.PACKET_HEADER, MaterialKind.HP_CANDIDATE),
            "ack_ranges", EnumSet.of(MaterialKind.ACK_RANGE),
            "key_phase", EnumSet.of(MaterialKind.DATAGRAM, MaterialKind.PACKET_HEADER,
                    MaterialKind.KEY_GENERATION, MaterialKind.DECRYPTION_CANDIDATE),
            "cid_lineage", EnumSet.of(MaterialKind.CID_EVENT, MaterialKind.PATH_EVENT),
            "timeline", EnumSet.of(MaterialKind.DATAGRAM, MaterialKind.PACKET_HEADER, MaterialKind.PATH_EVENT));

    public ViewResult compute(String caseId, String branch, String view, Long atSeq) {
        List<Material> materials = store.materialsVisible(caseId, branch, atSeq);
        Params params = paramsAt(caseId, branch, atSeq);
        DecisionState ds = decisionsAt(caseId, branch, atSeq);

        // View-local dependency sets: a source change only invalidates the views
        // that actually consume the changed material kind.
        Set<MaterialKind> kinds = DEPENDENCIES.getOrDefault(view, Set.of());
        boolean usesDecisions = "pn_spaces".equals(view) || "key_phase".equals(view);
        List<Material> relevant = materials.stream().filter(m -> kinds.contains(m.kind())).toList();
        List<Decision> decisions = store.decisionsVisible(caseId, branch, atSeq);

        List<String> inputIds = new ArrayList<>();
        for (Material m : relevant) inputIds.add(m.id());
        if (usesDecisions) for (Decision d : decisions) inputIds.add(d.id());
        String inputDigest = Digests.ofIds(inputIds) + ":" + params.version();

        var cached = store.derived(caseId, branch, view, inputDigest);
        if (cached.isPresent()) {
            Store.DerivedRow row = cached.get();
            List<Diagnostic> diags = new ArrayList<>();
            row.diagnostics().forEach(n -> diags.add(new Diagnostic(
                    n.get("position").asText(), n.get("code").asText(), n.get("message").asText())));
            return new ViewResult(row.id(), view, Status.valueOf(row.status()), row.payload(), diags,
                    row.parents().isEmpty() ? List.of() : List.of(row.parents().split(",")),
                    inputDigest, row.paramVersion(), true);
        }

        Budget budget = new Budget(params.budget());
        List<Diagnostic> diags = new ArrayList<>(usesDecisions ? ds.conflicts() : List.of());
        List<String> parents = new ArrayList<>();
        for (Material m : relevant) parents.add(m.id());
        if (usesDecisions) for (Decision d : decisions) parents.add(d.id());
        ObjectNode payload = om.createObjectNode();
        Status status = switch (view) {
            case "pn_spaces" -> computePnSpaces(relevant, ds, budget, payload, diags);
            case "ack_ranges" -> computeAckRanges(relevant, budget, payload, diags);
            case "key_phase" -> computeKeyPhase(relevant, ds, params, budget, payload, diags);
            case "cid_lineage" -> computeCidLineage(relevant, budget, payload, diags);
            case "timeline" -> computeTimeline(relevant, budget, payload, diags);
            default -> { diags.add(new Diagnostic("view:" + view, "UNKNOWN_VIEW", "no such view")); yield Status.SEMANTIC_UNSOLVABLE; }
        };
        if (usesDecisions && !ds.conflicts().isEmpty() && status == Status.OK) status = Status.SEMANTIC_UNSOLVABLE;

        String derId = "der-" + view + "-" + inputDigest.substring(0, 12);
        ArrayNode diagJson = om.createArrayNode();
        for (Diagnostic d : diags) {
            ObjectNode n = om.createObjectNode();
            n.put("position", d.position()); n.put("code", d.code()); n.put("message", d.message());
            diagJson.add(n);
        }
        store.saveDerived(derId, caseId, branch, view, inputDigest, params.version(),
                parents, status.name(), payload, diagJson, store.nextDerivedSeq(caseId));
        return new ViewResult(derId, view, status, payload, diags, parents, inputDigest, params.version(), false);
    }


    // ---------- pn_spaces ----------
    private Status computePnSpaces(List<Material> materials, DecisionState ds, Budget budget,
                                   ObjectNode payload, List<Diagnostic> diags) {
        Map<String, M.DatagramRec> datagrams = new LinkedHashMap<>();
        List<M.HeaderRec> headers = new ArrayList<>();
        Set<String> hpCovered = new HashSet<>();
        boolean incomplete = false;

        for (Material m : materials) {
            if (!budget.spendOne()) return Status.BUDGET_EXHAUSTED;
            switch (m.kind()) {
                case DATAGRAM -> {
                    var p = M.datagram(m);
                    diags.addAll(p.diagnostics());
                    if (p.ok()) datagrams.put(m.id(), p.value()); else incomplete = true;
                }
                case PACKET_HEADER -> {
                    var p = M.header(m);
                    diags.addAll(p.diagnostics());
                    if (p.ok()) headers.add(p.value()); else incomplete = true;
                }
                case HP_CANDIDATE -> {
                    var p = M.hpCandidate(m);
                    diags.addAll(p.diagnostics());
                    if (p.ok()) hpCovered.add(p.value().headerId()); else incomplete = true;
                }
                default -> {}
            }
        }

        // Packet-number spaces are isolated per (space, direction): Initial,
        // Handshake and Application chains never share expected_pn state.
        record ChainKey(String space, String direction) {}
        Map<ChainKey, List<M.HeaderRec>> chains = new TreeMap<>(Comparator
                .comparing(ChainKey::space).thenComparing(ChainKey::direction));
        for (M.HeaderRec h : headers) {
            M.DatagramRec dg = datagrams.get(h.datagramId());
            String dir = dg == null ? "unknown" : dg.direction();
            chains.computeIfAbsent(new ChainKey(h.space(), dir), k -> new ArrayList<>()).add(h);
        }

        ObjectNode spacesNode = om.createObjectNode();
        for (var e : chains.entrySet()) {
            List<M.HeaderRec> chain = e.getValue();
            chain.sort(Comparator
                    .comparingLong((M.HeaderRec h) -> datagrams.containsKey(h.datagramId())
                            ? datagrams.get(h.datagramId()).arrivalUs() : Long.MAX_VALUE)
                    .thenComparing(M.HeaderRec::id));
            long expected = 0;
            ArrayNode packets = om.createArrayNode();
            for (M.HeaderRec h : chain) {
                if (!budget.spendOne()) return Status.BUDGET_EXHAUSTED;
                ObjectNode pkt = om.createObjectNode();
                pkt.put("header_id", h.id());
                pkt.put("truncated_pn", h.truncatedPn());
                pkt.put("pn_bits", h.pnBits());
                pkt.put("unit", "packet-number");
                M.DatagramRec dg = datagrams.get(h.datagramId());
                if (dg == null) {
                    diags.add(new Diagnostic("material:" + h.id() + "#/datagram", "MISSING_FIELD",
                            "datagram " + h.datagramId() + " not present; header kept in place, not recovered"));
                    pkt.put("status", Status.INCOMPLETE_INPUT.name());
                    pkt.putNull("time_us");
                    packets.add(pkt);
                    incomplete = true;
                    continue;
                }
                pkt.put("time_us", dg.arrivalUs());
                pkt.put("time_base", M.TIME_UNIT);
                pkt.put("path", dg.path());
                if (!hpCovered.contains(h.id())) {
                    diags.add(new Diagnostic("material:" + h.id(), "MISSING_HP_CANDIDATE",
                            "no header-protection candidate; recovery deferred"));
                    pkt.put("status", Status.INCOMPLETE_INPUT.name());
                    pkt.put("expected_pn_at_arrival", expected);
                    packets.add(pkt);
                    incomplete = true;
                    continue;
                }
                PnRecovery.Result r = PnRecovery.recover(expected, h.truncatedPn(), h.pnBits());
                ArrayNode cands = om.createArrayNode();
                for (PnRecovery.Candidate c : r.candidates()) {
                    ObjectNode cn = om.createObjectNode();
                    String candId = "cand-" + h.id() + "-" + c.fullPn();
                    cn.put("id", candId);
                    cn.put("full_pn", c.fullPn());
                    cn.put("primary", c.primary());
                    cn.put("rationale", c.rationale());
                    List<Decision> decs = ds.liveByTarget().get(candId);
                    if (decs != null) {
                        ArrayNode da = om.createArrayNode();
                        for (Decision d : decs) {
                            ObjectNode dn = om.createObjectNode();
                            dn.put("decision_id", d.id());
                            dn.put("kind", d.kind());
                            da.add(dn);
                        }
                        cn.set("decisions", da);
                    }
                    cands.add(cn);
                }
                pkt.set("candidates", cands);
                pkt.put("window_multi_solution", !r.unique());
                pkt.put("expected_pn_at_arrival", expected);
                pkt.put("status", Status.OK.name());
                packets.add(pkt);
                expected = r.candidates().stream().filter(PnRecovery.Candidate::primary)
                        .findFirst().orElseThrow().fullPn() + 1;
            }
            ObjectNode dirNode = om.createObjectNode();
            dirNode.put("expected_next_pn", expected);
            dirNode.put("isolated", true);
            dirNode.set("packets", packets);
            ObjectNode spaceNode = spacesNode.withObjectProperty(e.getKey().space());
            spaceNode.withObjectProperty("directions").set(e.getKey().direction(), dirNode);
        }
        payload.set("spaces", spacesNode);
        payload.put("space_isolation",
                "Initial/Handshake/Application packet-number spaces are independent per direction");
        return incomplete ? Status.INCOMPLETE_INPUT : Status.OK;
    }

    // ---------- ack_ranges ----------
    private Status computeAckRanges(List<Material> materials, Budget budget,
                                    ObjectNode payload, List<Diagnostic> diags) {
        record Key(String space, String path) {}
        Map<Key, List<M.AckRangeRec>> grouped = new TreeMap<>(Comparator.comparing(Key::space).thenComparing(Key::path));
        Map<Key, List<String>> sources = new HashMap<>();
        boolean incomplete = false;
        for (Material m : materials) {
            if (m.kind() != MaterialKind.ACK_RANGE) continue;
            if (!budget.spendOne()) return Status.BUDGET_EXHAUSTED;
            var p = M.ackRange(m);
            diags.addAll(p.diagnostics());
            if (!p.ok()) { incomplete = true; continue; }
            Key k = new Key(p.value().space(), p.value().path());
            grouped.computeIfAbsent(k, x -> new ArrayList<>()).add(p.value());
            sources.computeIfAbsent(k, x -> new ArrayList<>()).add(m.id());
        }
        ArrayNode out = om.createArrayNode();
        for (var e : grouped.entrySet()) {
            if (!budget.spend(4)) return Status.BUDGET_EXHAUSTED;
            // Out-of-order arrival is normalised: merge by range, not by arrival order.
            List<long[]> all = new ArrayList<>();
            for (M.AckRangeRec r : e.getValue()) all.addAll(r.ranges());
            all.sort((a, b) -> Long.compare(a[0], b[0]) != 0 ? Long.compare(a[0], b[0]) : Long.compare(a[1], b[1]));
            List<long[]> merged = new ArrayList<>();
            for (long[] r : all) {
                if (!budget.spendOne()) return Status.BUDGET_EXHAUSTED;
                if (!merged.isEmpty() && r[0] <= merged.get(merged.size() - 1)[1] + 1) {
                    long[] last = merged.get(merged.size() - 1);
                    last[1] = Math.max(last[1], r[1]);
                } else {
                    merged.add(new long[]{r[0], r[1]});
                }
            }
            ObjectNode g = om.createObjectNode();
            g.put("space", e.getKey().space());
            g.put("path", e.getKey().path());
            g.put("unit", "packet-number");
            ArrayNode src = om.createArrayNode();
            sources.get(e.getKey()).stream().sorted().forEach(src::add);
            g.set("sources", src);
            ArrayNode arr = om.createArrayNode();
            for (long[] r : merged) {
                ObjectNode rn = om.createObjectNode();
                rn.put("smallest", r[0]); rn.put("largest", r[1]);
                arr.add(rn);
            }
            g.set("merged_ranges", arr);
            out.add(g);
        }
        payload.set("groups", out);
        return incomplete ? Status.INCOMPLETE_INPUT : Status.OK;
    }

    // ---------- key_phase ----------
    private Status computeKeyPhase(List<Material> materials, DecisionState ds, Params params, Budget budget,
                                   ObjectNode payload, List<Diagnostic> diags) {
        Map<String, M.DatagramRec> datagrams = new LinkedHashMap<>();
        Map<String, M.HeaderRec> headers = new LinkedHashMap<>();
        Map<String, M.KeyGenRec> keyGens = new LinkedHashMap<>();
        List<M.DecryptCandidateRec> attempts = new ArrayList<>();
        boolean incomplete = false;

        for (Material m : materials) {
            if (!budget.spendOne()) return Status.BUDGET_EXHAUSTED;
            switch (m.kind()) {
                case DATAGRAM -> { var p = M.datagram(m); diags.addAll(p.diagnostics());
                    if (p.ok()) datagrams.put(m.id(), p.value()); else incomplete = true; }
                case PACKET_HEADER -> { var p = M.header(m); diags.addAll(p.diagnostics());
                    if (p.ok()) headers.put(m.id(), p.value()); else incomplete = true; }
                case KEY_GENERATION -> { var p = M.keyGen(m); diags.addAll(p.diagnostics());
                    if (p.ok()) keyGens.put(m.id(), p.value()); else incomplete = true; }
                case DECRYPTION_CANDIDATE -> { var p = M.decryptCandidate(m); diags.addAll(p.diagnostics());
                    if (p.ok()) attempts.add(p.value()); else incomplete = true; }
                default -> {}
            }
        }

        Map<String, List<KeyPhaseTracker.Attempt>> byHeader = new LinkedHashMap<>();
        for (M.DecryptCandidateRec a : attempts) {
            if (!budget.spendOne()) return Status.BUDGET_EXHAUSTED;
            M.KeyGenRec kg = keyGens.get(a.keyGenId());
            if (kg == null) {
                diags.add(new Diagnostic("material:" + a.id() + "#/key_gen", "MISSING_FIELD",
                        "key generation " + a.keyGenId() + " not imported; attempt kept but unusable"));
                incomplete = true;
                continue;
            }
            if (!"application".equals(kg.space())) continue;
            byHeader.computeIfAbsent(a.headerId(), k -> new ArrayList<>())
                    .add(new KeyPhaseTracker.Attempt(a.id(), kg.generation(), a.ok(), a.fullPn()));
        }

        // Key-phase trajectories are tracked per direction; the two endpoints
        // update their sending keys independently.
        Map<String, List<M.HeaderRec>> byDirection = new TreeMap<>();
        for (M.HeaderRec h : headers.values()) {
            if (!"application".equals(h.space())) continue;
            M.DatagramRec dg0 = datagrams.get(h.datagramId());
            byDirection.computeIfAbsent(dg0 == null ? "unknown" : dg0.direction(),
                    k -> new ArrayList<>()).add(h);
        }

        ObjectNode directionsNode = om.createObjectNode();
        for (var dirEntry : byDirection.entrySet()) {
            List<M.HeaderRec> appHeaders = dirEntry.getValue().stream()
                    .sorted(Comparator
                            .comparingLong((M.HeaderRec h) -> datagrams.containsKey(h.datagramId())
                                    ? datagrams.get(h.datagramId()).arrivalUs() : Long.MAX_VALUE)
                            .thenComparing(M.HeaderRec::id))
                    .toList();
            List<KeyPhaseTracker.Packet> packets = new ArrayList<>();
            for (M.HeaderRec h : appHeaders) {
                if (!budget.spendOne()) return Status.BUDGET_EXHAUSTED;
                if (h.keyPhaseBit() == null) {
                    diags.add(new Diagnostic("material:" + h.id() + "#/key_phase_bit", "MISSING_FIELD",
                            "application packet without key phase bit"));
                    incomplete = true;
                    continue;
                }
                M.DatagramRec dg = datagrams.get(h.datagramId());
                if (dg == null) {
                    diags.add(new Diagnostic("material:" + h.id() + "#/datagram", "MISSING_FIELD",
                            "datagram " + h.datagramId() + " not present"));
                    incomplete = true;
                    continue;
                }
                packets.add(new KeyPhaseTracker.Packet(h.id(), dg.arrivalUs(), h.keyPhaseBit(),
                        byHeader.getOrDefault(h.id(), List.of())));
            }

            KeyPhaseTracker.Track track = KeyPhaseTracker.run(packets,
                    new KeyPhaseTracker.Params(params.confirmPackets(), params.gracePackets()));

            ArrayNode verdicts = om.createArrayNode();
            for (KeyPhaseTracker.Verdict v : track.verdicts()) {
                ObjectNode n = om.createObjectNode();
                n.put("header_id", v.headerId());
                n.put("time_us", v.arrivalUs());
                n.put("time_base", M.TIME_UNIT);
                n.put("outcome", v.outcome());
                n.put("generation", v.generation());
                if (v.candidateId() != null) n.put("candidate_id", v.candidateId());
                n.put("reason", v.reason());
                List<Decision> decs = ds.liveByTarget().get("flip:" + v.headerId());
                if (decs != null) {
                    ArrayNode da = om.createArrayNode();
                    for (Decision d : decs) {
                        ObjectNode dn = om.createObjectNode();
                        dn.put("decision_id", d.id());
                        dn.put("kind", d.kind());
                        dn.put("rationale", d.payload().path("rationale").asText(""));
                        da.add(dn);
                    }
                    n.set("decisions", da);
                }
                verdicts.add(n);
            }
            ArrayNode segs = om.createArrayNode();
            for (int[] seg : track.committedGenerations()) {
                ObjectNode n = om.createObjectNode();
                n.put("generation", seg[0]);
                n.put("from_packet_index", seg[1]);
                segs.add(n);
            }
            ObjectNode dirNode = om.createObjectNode();
            dirNode.set("verdicts", verdicts);
            dirNode.set("committed_generations", segs);
            directionsNode.set(dirEntry.getKey(), dirNode);
        }
        payload.set("directions", directionsNode);
        payload.put("confirm_packets", params.confirmPackets());
        payload.put("grace_packets", params.gracePackets());
        payload.put("commit_rule", "key phase flip commits only after successful decryption and the confirmation rule");
        return status(incomplete);
    }

    private Status status(boolean incomplete) { return incomplete ? Status.INCOMPLETE_INPUT : Status.OK; }

    // ---------- cid_lineage ----------
    private Status computeCidLineage(List<Material> materials, Budget budget,
                                     ObjectNode payload, List<Diagnostic> diags) {
        List<M.CidEventRec> events = new ArrayList<>();
        List<M.PathEventRec> paths = new ArrayList<>();
        boolean incomplete = false;
        for (Material m : materials) {
            if (!budget.spendOne()) return Status.BUDGET_EXHAUSTED;
            if (m.kind() == MaterialKind.CID_EVENT) {
                var p = M.cidEvent(m);
                diags.addAll(p.diagnostics());
                if (p.ok()) events.add(p.value()); else incomplete = true;
            } else if (m.kind() == MaterialKind.PATH_EVENT) {
                var p = M.pathEvent(m);
                diags.addAll(p.diagnostics());
                if (p.ok()) paths.add(p.value()); else incomplete = true;
            }
        }
        // Stable order: cid sequence, then time, then material id. Equivalent inputs
        // in any arrival order produce the same lineage.
        events.sort(Comparator.comparingLong(M.CidEventRec::cidSeq)
                .thenComparingLong(M.CidEventRec::timeUs).thenComparing(M.CidEventRec::id));

        Set<String> issued = new HashSet<>();
        ArrayNode nodes = om.createArrayNode();
        for (M.CidEventRec e : events) {
            if (!budget.spendOne()) return Status.BUDGET_EXHAUSTED;
            ObjectNode n = om.createObjectNode();
            n.put("event_id", e.id());
            n.put("cid", e.cid());
            n.put("action", e.action());
            n.put("cid_seq", e.cidSeq());
            n.put("path", e.path());
            n.put("time_us", e.timeUs());
            n.put("time_base", M.TIME_UNIT);
            if ("ISSUE".equals(e.action())) issued.add(e.cid());
            if (("RETIRE".equals(e.action()) || "SELECT".equals(e.action())) && !issued.contains(e.cid())) {
                diags.add(new Diagnostic("material:" + e.id() + "#/cid", "SEMANTIC_UNSOLVABLE",
                        e.action() + " of cid " + e.cid() + " before any ISSUE; event kept in place"));
                n.put("orphan", true);
            }
            nodes.add(n);
        }
        ArrayNode lanes = om.createArrayNode();
        paths.sort(Comparator.comparingLong(M.PathEventRec::timeUs).thenComparing(M.PathEventRec::id));
        for (M.PathEventRec p : paths) {
            ObjectNode n = om.createObjectNode();
            n.put("event_id", p.id());
            n.put("path", p.path());
            n.put("action", p.action());
            n.put("four_tuple", p.fourTuple());
            n.put("time_us", p.timeUs());
            n.put("time_base", M.TIME_UNIT);
            if ("MIGRATED".equals(p.action()))
                n.put("note", "five-tuple change does not cut the connection; CID lineage continues");
            lanes.add(n);
        }
        payload.set("cid_events", nodes);
        payload.set("path_events", lanes);
        return status(incomplete);
    }

    // ---------- timeline ----------
    private Status computeTimeline(List<Material> materials, Budget budget,
                                   ObjectNode payload, List<Diagnostic> diags) {
        Map<String, M.DatagramRec> datagrams = new LinkedHashMap<>();
        Map<String, M.HeaderRec> headers = new LinkedHashMap<>();
        List<M.PathEventRec> paths = new ArrayList<>();
        boolean incomplete = false;
        for (Material m : materials) {
            if (!budget.spendOne()) return Status.BUDGET_EXHAUSTED;
            switch (m.kind()) {
                case DATAGRAM -> { var p = M.datagram(m); diags.addAll(p.diagnostics());
                    if (p.ok()) datagrams.put(m.id(), p.value()); else incomplete = true; }
                case PACKET_HEADER -> { var p = M.header(m); diags.addAll(p.diagnostics());
                    if (p.ok()) headers.put(m.id(), p.value()); else incomplete = true; }
                case PATH_EVENT -> { var p = M.pathEvent(m); diags.addAll(p.diagnostics());
                    if (p.ok()) paths.add(p.value()); else incomplete = true; }
                default -> {}
            }
        }
        Set<String> lanes = new TreeSet<>();
        ArrayNode points = om.createArrayNode();
        for (M.DatagramRec dg : datagrams.values()) {
            if (!budget.spendOne()) return Status.BUDGET_EXHAUSTED;
            lanes.add(dg.path());
            ObjectNode n = om.createObjectNode();
            n.put("datagram_id", dg.id());
            n.put("path", dg.path());
            n.put("direction", dg.direction());
            n.put("time_us", dg.arrivalUs());
            n.put("time_base", M.TIME_UNIT);
            n.put("bytes", dg.bytesHex().length() / 2);
            n.put("byte_unit", "byte");
            List<M.HeaderRec> hs = headers.values().stream()
                    .filter(h -> h.datagramId().equals(dg.id()))
                    .sorted(Comparator.comparing(M.HeaderRec::id)).toList();
            ArrayNode ha = om.createArrayNode();
            for (M.HeaderRec h : hs) {
                ObjectNode hn = om.createObjectNode();
                hn.put("header_id", h.id());
                hn.put("space", h.space());
                hn.put("truncated_pn", h.truncatedPn());
                hn.put("pn_bits", h.pnBits());
                if (h.keyPhaseBit() != null) hn.put("key_phase_bit", h.keyPhaseBit());
                ha.add(hn);
            }
            n.set("headers", ha);
            points.add(n);
        }
        ArrayNode pathEvents = om.createArrayNode();
        paths.sort(Comparator.comparingLong(M.PathEventRec::timeUs).thenComparing(M.PathEventRec::id));
        for (M.PathEventRec p : paths) {
            lanes.add(p.path());
            ObjectNode n = om.createObjectNode();
            n.put("event_id", p.id());
            n.put("path", p.path());
            n.put("action", p.action());
            n.put("four_tuple", p.fourTuple());
            n.put("time_us", p.timeUs());
            pathEvents.add(n);
        }
        ArrayNode laneArr = om.createArrayNode();
        lanes.forEach(laneArr::add);
        payload.set("lanes", laneArr);
        payload.set("points", points);
        payload.set("path_events", pathEvents);
        payload.put("time_base", M.TIME_UNIT);
        return status(incomplete);
    }
}
