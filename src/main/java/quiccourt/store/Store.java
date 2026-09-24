package quiccourt.store;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import quiccourt.model.Decision;
import quiccourt.model.Material;
import quiccourt.model.MaterialKind;

import java.sql.*;
import java.util.*;

/** SQLite-backed event-sourced store. Materials are immutable rows; events,
 *  decisions and derived results are append-only. Branches fork with
 *  parent_branch/fork_seq so an old event restores the exact visible horizon. */
public final class Store implements AutoCloseable {
    private final Connection conn;
    private final ObjectMapper mapper;

    public Store(String jdbcUrl, ObjectMapper mapper) {
        this.mapper = mapper;
        try {
            conn = DriverManager.getConnection(jdbcUrl);
            conn.createStatement().execute("PRAGMA foreign_keys=ON");
            init();
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }

    private void init() throws SQLException {
        try (Statement st = conn.createStatement()) {
            st.executeUpdate("CREATE TABLE IF NOT EXISTS cases(id TEXT PRIMARY KEY, name TEXT NOT NULL, created_at INTEGER NOT NULL, time_base TEXT NOT NULL, description TEXT)");
            st.executeUpdate("CREATE TABLE IF NOT EXISTS branches(case_id TEXT NOT NULL, name TEXT NOT NULL, parent_branch TEXT, fork_seq INTEGER, PRIMARY KEY(case_id,name))");
            st.executeUpdate("CREATE TABLE IF NOT EXISTS events(id TEXT PRIMARY KEY, case_id TEXT NOT NULL, branch TEXT NOT NULL, seq INTEGER NOT NULL, kind TEXT NOT NULL, payload TEXT NOT NULL, input_digest TEXT, created_at INTEGER NOT NULL, UNIQUE(case_id,branch,seq))");
            st.executeUpdate("CREATE TABLE IF NOT EXISTS materials(id TEXT PRIMARY KEY, case_id TEXT NOT NULL, branch TEXT NOT NULL, seq INTEGER NOT NULL, kind TEXT NOT NULL, raw TEXT NOT NULL, digest TEXT NOT NULL, introduced_by_event TEXT NOT NULL, UNIQUE(case_id,seq))");
            st.executeUpdate("CREATE TABLE IF NOT EXISTS decisions(id TEXT PRIMARY KEY, case_id TEXT NOT NULL, branch TEXT NOT NULL, seq INTEGER NOT NULL, kind TEXT NOT NULL, target_id TEXT NOT NULL, payload TEXT NOT NULL, supersedes TEXT, introduced_by_event TEXT NOT NULL, UNIQUE(case_id,seq))");
            st.executeUpdate("CREATE TABLE IF NOT EXISTS derived(id TEXT PRIMARY KEY, case_id TEXT NOT NULL, branch TEXT NOT NULL, view TEXT NOT NULL, input_digest TEXT NOT NULL, param_version TEXT NOT NULL, parents TEXT NOT NULL, status TEXT NOT NULL, payload TEXT NOT NULL, diagnostics TEXT NOT NULL, seq INTEGER NOT NULL)");
            st.executeUpdate("CREATE INDEX IF NOT EXISTS ix_derived_lookup ON derived(case_id,branch,view,input_digest)");
            st.executeUpdate("CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT)");
        }
    }

    public ObjectMapper mapper() { return mapper; }
    public Connection connection() { return conn; }

    public void putCase(String id, String name, String timeBase, String description) {
        try (PreparedStatement ps = conn.prepareStatement(
                "INSERT OR REPLACE INTO cases(id,name,created_at,time_base,description) VALUES(?,?,?,?,?)")) {
            ps.setString(1, id); ps.setString(2, name);
            ps.setLong(3, System.currentTimeMillis()); ps.setString(4, timeBase); ps.setString(5, description);
            ps.executeUpdate();
        } catch (SQLException e) { throw new RuntimeException(e); }
        ensureBranch(id, "main", null, null);
    }

    public void ensureBranch(String caseId, String branch, String parentBranch, Long forkSeq) {
        try (PreparedStatement ps = conn.prepareStatement(
                "INSERT OR IGNORE INTO branches(case_id,name,parent_branch,fork_seq) VALUES(?,?,?,?)")) {
            ps.setString(1, caseId); ps.setString(2, branch);
            ps.setString(3, parentBranch);
            if (forkSeq == null) ps.setNull(4, Types.INTEGER); else ps.setLong(4, forkSeq);
            ps.executeUpdate();
        } catch (SQLException e) { throw new RuntimeException(e); }
    }

    public record BranchInfo(String name, String parent, Long forkSeq) {}

    public Map<String, BranchInfo> branches(String caseId) {
        Map<String, BranchInfo> out = new LinkedHashMap<>();
        try (PreparedStatement ps = conn.prepareStatement(
                "SELECT name,parent_branch,fork_seq FROM branches WHERE case_id=? ORDER BY name")) {
            ps.setString(1, caseId);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) out.put(rs.getString(1),
                        new BranchInfo(rs.getString(1), rs.getString(2),
                                rs.getObject(3) == null ? null : rs.getLong(3)));
            }
        } catch (SQLException e) { throw new RuntimeException(e); }
        return out;
    }

    public List<String> listCases() {
        List<String> out = new ArrayList<>();
        try (Statement st = conn.createStatement();
             ResultSet rs = st.executeQuery("SELECT id FROM cases ORDER BY created_at,id")) {
            while (rs.next()) out.add(rs.getString(1));
        } catch (SQLException e) { throw new RuntimeException(e); }
        return out;
    }

    public record CaseRow(String id, String name, String timeBase, String description) {}

    public CaseRow caseRow(String id) {
        try (PreparedStatement ps = conn.prepareStatement("SELECT id,name,time_base,description FROM cases WHERE id=?")) {
            ps.setString(1, id);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) return new CaseRow(rs.getString(1), rs.getString(2), rs.getString(3), rs.getString(4));
            }
        } catch (SQLException e) { throw new RuntimeException(e); }
        return null;
    }

    /** events: per-branch monotonic; materials/decisions: per-case global stable order. */
    public long nextSeq(String caseId, String branch, String table) {
        boolean perCase = table.equals("materials") || table.equals("decisions");
        String sql = perCase
                ? "SELECT COALESCE(MAX(seq),0)+1 FROM " + table + " WHERE case_id=?"
                : "SELECT COALESCE(MAX(seq),0)+1 FROM " + table + " WHERE case_id=? AND branch=?";
        try (PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, caseId);
            if (!perCase) ps.setString(2, branch);
            try (ResultSet rs = ps.executeQuery()) { rs.next(); return rs.getLong(1); }
        } catch (SQLException e) { throw new RuntimeException(e); }
    }

    public void appendEvent(String id, String caseId, String branch, long seq, String kind,
                            JsonNode payload, String inputDigest) {
        try (PreparedStatement ps = conn.prepareStatement(
                "INSERT INTO events(id,case_id,branch,seq,kind,payload,input_digest,created_at) VALUES(?,?,?,?,?,?,?,?)")) {
            ps.setString(1, id); ps.setString(2, caseId); ps.setString(3, branch); ps.setLong(4, seq);
            ps.setString(5, kind); ps.setString(6, mapper.writeValueAsString(payload));
            ps.setString(7, inputDigest); ps.setLong(8, System.currentTimeMillis());
            ps.executeUpdate();
        } catch (Exception e) { throw new RuntimeException(e); }
    }

    public void appendMaterial(Material m) {
        try (PreparedStatement ps = conn.prepareStatement(
                "INSERT INTO materials(id,case_id,branch,seq,kind,raw,digest,introduced_by_event) VALUES(?,?,?,?,?,?,?,?)")) {
            ps.setString(1, m.id()); ps.setString(2, m.caseId()); ps.setString(3, m.branch()); ps.setLong(4, m.seq());
            ps.setString(5, m.kind().name()); ps.setString(6, mapper.writeValueAsString(m.raw()));
            ps.setString(7, m.digest()); ps.setString(8, m.introducedByEvent());
            ps.executeUpdate();
        } catch (Exception e) { throw new RuntimeException(e); }
    }

    public void appendDecision(Decision d) {
        try (PreparedStatement ps = conn.prepareStatement(
                "INSERT INTO decisions(id,case_id,branch,seq,kind,target_id,payload,supersedes,introduced_by_event) VALUES(?,?,?,?,?,?,?,?,?)")) {
            ps.setString(1, d.id()); ps.setString(2, d.caseId()); ps.setString(3, d.branch()); ps.setLong(4, d.seq());
            ps.setString(5, d.kind()); ps.setString(6, d.targetId()); ps.setString(7, mapper.writeValueAsString(d.payload()));
            ps.setString(8, d.supersedes()); ps.setString(9, d.introducedByEvent());
            ps.executeUpdate();
        } catch (Exception e) { throw new RuntimeException(e); }
    }

    public record EventRow(String id, String branch, long seq, String kind, JsonNode payload, String inputDigest) {}

    /** Visible horizon: events on this branch with seq <= atSeq, plus parent-branch
     *  events up to the fork point, recursively. */
    public List<EventRow> eventsVisible(String caseId, String branch, Long atSeq) {
        Map<String, BranchInfo> bs = branches(caseId);
        List<String[]> chain = new ArrayList<>();
        String cur = branch;
        Long cutoff = atSeq;
        while (cur != null) {
            chain.add(new String[]{cur, cutoff == null ? "" : cutoff.toString()});
            BranchInfo bi = bs.get(cur);
            if (bi == null) break;
            cur = bi.parent();
            cutoff = bi.forkSeq();
        }
        List<EventRow> out = new ArrayList<>();
        for (String[] c : chain) {
            String sql = "SELECT id,branch,seq,kind,payload,input_digest FROM events WHERE case_id=? AND branch=?"
                    + (c[1].isEmpty() ? "" : " AND seq<=" + Long.parseLong(c[1])) + " ORDER BY seq";
            try (PreparedStatement ps = conn.prepareStatement(sql)) {
                ps.setString(1, caseId); ps.setString(2, c[0]);
                try (ResultSet rs = ps.executeQuery()) {
                    while (rs.next()) out.add(new EventRow(rs.getString(1), rs.getString(2),
                            rs.getLong(3), rs.getString(4),
                            mapper.readTree(rs.getString(5)), rs.getString(6)));
                }
            } catch (Exception e) { throw new RuntimeException(e); }
        }
        out.sort(Comparator.comparingLong(EventRow::seq));
        return out;
    }

    public List<EventRow> allEvents(String caseId) {
        List<EventRow> out = new ArrayList<>();
        try (PreparedStatement ps = conn.prepareStatement(
                "SELECT id,branch,seq,kind,payload,input_digest FROM events WHERE case_id=? ORDER BY seq,branch")) {
            ps.setString(1, caseId);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) out.add(new EventRow(rs.getString(1), rs.getString(2),
                        rs.getLong(3), rs.getString(4), mapper.readTree(rs.getString(5)), rs.getString(6)));
            }
        } catch (Exception e) { throw new RuntimeException(e); }
        return out;
    }

    /** All materials visible at (branch, atSeq): introduced by an event in the horizon. */
    public List<Material> materialsVisible(String caseId, String branch, Long atSeq) {
        Set<String> horizon = new HashSet<>();
        for (EventRow e : eventsVisible(caseId, branch, atSeq)) horizon.add(e.id());
        List<Material> out = new ArrayList<>();
        try (PreparedStatement ps = conn.prepareStatement(
                "SELECT id,branch,seq,kind,raw,digest,introduced_by_event FROM materials WHERE case_id=? ORDER BY seq")) {
            ps.setString(1, caseId);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    if (horizon.contains(rs.getString(7))) out.add(toMaterial(caseId, rs));
                }
            }
        } catch (Exception e) { throw new RuntimeException(e); }
        return out;
    }

    public List<Material> allMaterials(String caseId) {
        List<Material> out = new ArrayList<>();
        try (PreparedStatement ps = conn.prepareStatement(
                "SELECT id,branch,seq,kind,raw,digest,introduced_by_event FROM materials WHERE case_id=? ORDER BY seq")) {
            ps.setString(1, caseId);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) out.add(toMaterial(caseId, rs));
            }
        } catch (Exception e) { throw new RuntimeException(e); }
        return out;
    }

    private Material toMaterial(String caseId, ResultSet rs) throws Exception {
        return new Material(rs.getString(1), caseId, rs.getString(2), rs.getLong(3),
                MaterialKind.valueOf(rs.getString(4)), mapper.readTree(rs.getString(5)),
                rs.getString(6), rs.getString(7));
    }

    public List<Decision> decisionsVisible(String caseId, String branch, Long atSeq) {
        Set<String> horizon = new HashSet<>();
        for (EventRow e : eventsVisible(caseId, branch, atSeq)) horizon.add(e.id());
        List<Decision> out = new ArrayList<>();
        try (PreparedStatement ps = conn.prepareStatement(
                "SELECT id,branch,seq,kind,target_id,payload,supersedes,introduced_by_event FROM decisions WHERE case_id=? ORDER BY seq")) {
            ps.setString(1, caseId);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    if (horizon.contains(rs.getString(8))) out.add(new Decision(rs.getString(1), caseId,
                            rs.getString(2), rs.getLong(3), rs.getString(4), rs.getString(5),
                            mapper.readTree(rs.getString(6)), rs.getString(7), rs.getString(8)));
                }
            }
        } catch (Exception e) { throw new RuntimeException(e); }
        return out;
    }

    public List<Decision> allDecisions(String caseId) {
        List<Decision> out = new ArrayList<>();
        try (PreparedStatement ps = conn.prepareStatement(
                "SELECT id,branch,seq,kind,target_id,payload,supersedes,introduced_by_event FROM decisions WHERE case_id=? ORDER BY seq")) {
            ps.setString(1, caseId);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) out.add(new Decision(rs.getString(1), caseId,
                        rs.getString(2), rs.getLong(3), rs.getString(4), rs.getString(5),
                        mapper.readTree(rs.getString(6)), rs.getString(7), rs.getString(8)));
            }
        } catch (Exception e) { throw new RuntimeException(e); }
        return out;
    }

    public void saveDerived(String id, String caseId, String branch, String view,
                            String inputDigest, String paramVersion, List<String> parents,
                            String status, JsonNode payload, JsonNode diagnostics, long seq) {
        try (PreparedStatement ps = conn.prepareStatement(
                "INSERT OR REPLACE INTO derived(id,case_id,branch,view,input_digest,param_version,parents,status,payload,diagnostics,seq) VALUES(?,?,?,?,?,?,?,?,?,?,?)")) {
            ps.setString(1, id); ps.setString(2, caseId); ps.setString(3, branch); ps.setString(4, view);
            ps.setString(5, inputDigest); ps.setString(6, paramVersion);
            ps.setString(7, String.join(",", parents));
            ps.setString(8, status); ps.setString(9, mapper.writeValueAsString(payload));
            ps.setString(10, mapper.writeValueAsString(diagnostics)); ps.setLong(11, seq);
            ps.executeUpdate();
        } catch (Exception e) { throw new RuntimeException(e); }
    }

    public record DerivedRow(String id, String branch, String view, String inputDigest, String paramVersion,
                             String parents, String status, JsonNode payload, JsonNode diagnostics, long seq) {}

    public Optional<DerivedRow> derived(String caseId, String branch, String view, String inputDigest) {
        try (PreparedStatement ps = conn.prepareStatement(
                "SELECT id,branch,view,input_digest,param_version,parents,status,payload,diagnostics,seq FROM derived WHERE case_id=? AND branch=? AND view=? AND input_digest=? ORDER BY seq DESC")) {
            ps.setString(1, caseId); ps.setString(2, branch); ps.setString(3, view); ps.setString(4, inputDigest);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) return Optional.of(new DerivedRow(rs.getString(1), rs.getString(2), rs.getString(3),
                        rs.getString(4), rs.getString(5), rs.getString(6), rs.getString(7),
                        mapper.readTree(rs.getString(8)), mapper.readTree(rs.getString(9)), rs.getLong(10)));
            }
        } catch (Exception e) { throw new RuntimeException(e); }
        return Optional.empty();
    }

    public List<DerivedRow> derivedFor(String caseId, String branch) {
        List<DerivedRow> out = new ArrayList<>();
        try (PreparedStatement ps = conn.prepareStatement(
                "SELECT id,branch,view,input_digest,param_version,parents,status,payload,diagnostics,seq FROM derived WHERE case_id=? AND branch=? ORDER BY seq")) {
            ps.setString(1, caseId); ps.setString(2, branch);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) out.add(new DerivedRow(rs.getString(1), rs.getString(2), rs.getString(3),
                        rs.getString(4), rs.getString(5), rs.getString(6), rs.getString(7),
                        mapper.readTree(rs.getString(8)), mapper.readTree(rs.getString(9)), rs.getLong(10)));
            }
        } catch (Exception e) { throw new RuntimeException(e); }
        return out;
    }

    public long nextDerivedSeq(String caseId) {
        try (PreparedStatement ps = conn.prepareStatement("SELECT COALESCE(MAX(seq),0)+1 FROM derived WHERE case_id=?")) {
            ps.setString(1, caseId);
            try (ResultSet rs = ps.executeQuery()) { rs.next(); return rs.getLong(1); }
        } catch (SQLException e) { throw new RuntimeException(e); }
    }

    public String meta(String key) {
        try (PreparedStatement ps = conn.prepareStatement("SELECT value FROM meta WHERE key=?")) {
            ps.setString(1, key);
            try (ResultSet rs = ps.executeQuery()) { return rs.next() ? rs.getString(1) : null; }
        } catch (SQLException e) { throw new RuntimeException(e); }
    }

    public void putMeta(String key, String value) {
        try (PreparedStatement ps = conn.prepareStatement("INSERT OR REPLACE INTO meta(key,value) VALUES(?,?)")) {
            ps.setString(1, key); ps.setString(2, value); ps.executeUpdate();
        } catch (SQLException e) { throw new RuntimeException(e); }
    }

    /** Id allocation that survives export/import: counters live in meta, never guessed. */
    public String nextId(String prefix) {
        String cur = meta("ctr:" + prefix);
        long n = cur == null ? 1 : Long.parseLong(cur) + 1;
        putMeta("ctr:" + prefix, Long.toString(n));
        return prefix + "-" + String.format("%04d", n);
    }

    /** Raise a counter after import so reused identities never collide. */
    public void raiseCounter(String prefix, String id) {
        if (id == null || !id.startsWith(prefix + "-")) return;
        try {
            long n = Long.parseLong(id.substring(prefix.length() + 1));
            String cur = meta("ctr:" + prefix);
            long c = cur == null ? 0 : Long.parseLong(cur);
            if (n > c) putMeta("ctr:" + prefix, Long.toString(n));
        } catch (NumberFormatException ignored) {}
    }

    public void deleteCase(String caseId) {
        String[] tables = {"derived", "decisions", "materials", "events", "branches", "cases"};
        try {
            for (String t : tables) {
                try (PreparedStatement ps = conn.prepareStatement("DELETE FROM " + t + " WHERE case_id=?")) {
                    ps.setString(1, caseId); ps.executeUpdate();
                }
            }
        } catch (SQLException e) { throw new RuntimeException(e); }
    }

    public void begin() { try { conn.setAutoCommit(false); } catch (SQLException e) { throw new RuntimeException(e); } }
    public void commit() { try { conn.commit(); conn.setAutoCommit(true); } catch (SQLException e) { throw new RuntimeException(e); } }
    public void rollback() { try { conn.rollback(); conn.setAutoCommit(true); } catch (SQLException e) { throw new RuntimeException(e); } }

    @Override public void close() {
        try { conn.close(); } catch (SQLException ignored) {}
    }
}
