package quictribunal.store;

import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;

import quictribunal.model.Domain.CidEvent;
import quictribunal.model.Domain.Computation;
import quictribunal.model.Domain.Datagram;
import quictribunal.model.Domain.Decision;
import quictribunal.model.Domain.Direction;
import quictribunal.model.Domain.Event;
import quictribunal.model.Domain.EventType;
import quictribunal.model.Domain.HpCandidate;
import quictribunal.model.Domain.KeyGen;
import quictribunal.model.Domain.KeyRole;
import quictribunal.model.Domain.Packet;
import quictribunal.model.Domain.PathInfo;
import quictribunal.model.Domain.PnSpace;

/**
 * SQLite-backed append-only event log plus immutable material tables and a computation audit
 * trail. Every multi-statement mutation runs inside {@link #tx(Store.RunnableEx)}; a failure
 * (or an injected fault used by the half-write tests) rolls back completely.
 */
public final class Store implements AutoCloseable {
    private final Connection conn;
    private final String url;

    public Store(Path dbFile) {
        this("jdbc:sqlite:" + dbFile.toAbsolutePath());
    }

    public Store(String jdbcUrl) {
        this.url = jdbcUrl;
        try {
            Class.forName("org.sqlite.JDBC");
            this.conn = DriverManager.getConnection(jdbcUrl);
            this.conn.setAutoCommit(false);
            try (Statement st = conn.createStatement()) {
                st.execute("PRAGMA foreign_keys = ON");
                st.execute("PRAGMA journal_mode = WAL");
                st.execute("PRAGMA synchronous = FULL");
            }
            conn.commit();
            initSchema();
        } catch (Exception e) {
            throw new IllegalStateException("cannot open store: " + jdbcUrl, e);
        }
    }

    public String url() {
        return url;
    }

    public Connection connection() {
        return conn;
    }

    private void initSchema() throws SQLException {
        ddl("CREATE TABLE IF NOT EXISTS project_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)");
        ddl("CREATE TABLE IF NOT EXISTS events ("
                + "seq INTEGER PRIMARY KEY AUTOINCREMENT,"
                + "id TEXT UNIQUE NOT NULL,"
                + "type TEXT NOT NULL,"
                + "branch TEXT,"
                + "root_seq INTEGER,"
                + "at_ns INTEGER NOT NULL,"
                + "parent_id TEXT NOT NULL,"
                + "payload TEXT NOT NULL)");
        ddl("CREATE TABLE IF NOT EXISTS datagrams ("
                + "id TEXT PRIMARY KEY, t_ns INTEGER NOT NULL, dir TEXT NOT NULL,"
                + "path_id TEXT NOT NULL, bytes_hex TEXT NOT NULL,"
                + "replaced_by TEXT)");
        ddl("CREATE TABLE IF NOT EXISTS hp_candidates ("
                + "id TEXT PRIMARY KEY, packet_id TEXT NOT NULL, mask_hex TEXT NOT NULL,"
                + "applied INTEGER NOT NULL, note TEXT NOT NULL)");
        ddl("CREATE TABLE IF NOT EXISTS packets ("
                + "id TEXT PRIMARY KEY, datagram_id TEXT NOT NULL, offset INTEGER NOT NULL,"
                + "space TEXT NOT NULL, long_header INTEGER NOT NULL, version INTEGER NOT NULL,"
                + "dcid_hex TEXT, scid_hex TEXT, key_generation INTEGER NOT NULL,"
                + "key_phase_bit INTEGER, truncated_pn INTEGER NOT NULL, pn_len INTEGER NOT NULL,"
                + "decryptable_gens TEXT NOT NULL, ack_frame_hex TEXT, raw_header_hex TEXT NOT NULL)");
        ddl("CREATE TABLE IF NOT EXISTS key_gens ("
                + "id TEXT PRIMARY KEY, role TEXT NOT NULL, generation INTEGER NOT NULL,"
                + "valid_from_ns INTEGER NOT NULL, valid_until_ns INTEGER,"
                + "secret_label TEXT NOT NULL)");
        ddl("CREATE TABLE IF NOT EXISTS cid_events ("
                + "id TEXT PRIMARY KEY, seq INTEGER NOT NULL, cid_hex TEXT NOT NULL,"
                + "issued_ns INTEGER NOT NULL, retired_ns INTEGER, issued_on_path_id TEXT)");
        ddl("CREATE TABLE IF NOT EXISTS paths (id TEXT PRIMARY KEY, four_tuple TEXT NOT NULL)");
        ddl("CREATE TABLE IF NOT EXISTS decisions ("
                + "id TEXT PRIMARY KEY, type TEXT NOT NULL, target_id TEXT NOT NULL,"
                + "chosen_value TEXT, rationale TEXT NOT NULL, author TEXT NOT NULL,"
                + "at_ns INTEGER NOT NULL, branch TEXT, root_seq INTEGER)");
        ddl("CREATE TABLE IF NOT EXISTS computations ("
                + "id TEXT PRIMARY KEY, kind TEXT NOT NULL, input_digest TEXT NOT NULL,"
                + "params_version INTEGER NOT NULL, parent_ids TEXT NOT NULL,"
                + "result_json TEXT NOT NULL, invalidated_at_seq INTEGER,"
                + "invalid_reason TEXT, at_ns INTEGER NOT NULL, branch TEXT, root_seq INTEGER)");
        conn.commit();
    }

    private void ddl(String sql) throws SQLException {
        try (Statement st = conn.createStatement()) {
            st.execute(sql);
        }
    }

    public void tx(RunnableEx body) {
        try {
            body.run();
            conn.commit();
        } catch (RuntimeException e) {
            rollback();
            throw e;
        } catch (Exception e) {
            rollback();
            throw new RuntimeException(e);
        }
    }

    /** Test hook allowing a fault to be injected mid-transaction. */
    public void txWithFault(RunnableEx body) {
        try {
            body.run();
            throw new SQLException("injected crash before commit");
        } catch (Exception e) {
            rollback();
            throw new RuntimeException(e);
        }
    }

    public interface RunnableEx {
        void run() throws Exception;
    }

    private void rollback() {
        try {
            conn.rollback();
        } catch (SQLException ignored) {
            // rollback failure leaves the connection aborted; callers re-open
        }
    }

    private static void setLong(PreparedStatement ps, int idx, Long value) throws SQLException {
        if (value == null) ps.setNull(idx, java.sql.Types.INTEGER);
        else ps.setLong(idx, value);
    }

    private static Long getLong(ResultSet rs, String col) throws SQLException {
        long v = rs.getLong(col);
        return rs.wasNull() ? null : v;
    }

    private static String nz(String s) {
        return s == null ? "" : s;
    }

    // ---------------------------------------------------------------- meta

    public void putMeta(String key, String value) {
        try (PreparedStatement ps = conn.prepareStatement(
                "INSERT INTO project_meta(key, value) VALUES(?, ?) "
                        + "ON CONFLICT(key) DO UPDATE SET value = excluded.value")) {
            ps.setString(1, key);
            ps.setString(2, value);
            ps.executeUpdate();
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }

    public String getMeta(String key) {
        try (PreparedStatement ps = conn.prepareStatement(
                "SELECT value FROM project_meta WHERE key = ?")) {
            ps.setString(1, key);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next() ? rs.getString(1) : null;
            }
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }

    public boolean isEmpty() {
        try (Statement st = conn.createStatement();
             ResultSet rs = st.executeQuery("SELECT COUNT(*) FROM events")) {
            rs.next();
            return rs.getInt(1) == 0;
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }

    // ------------------------------------------------------------- events

    public Event appendEvent(EventType type, String branch, Long rootSeq,
                             String parentId, long atNs, String payloadJson) {
        String id = quictribunal.model.Ids.of("ev",
                type.name() + "|" + nz(branch) + "|" + rootSeq + "|" + nz(parentId) + "|" + payloadJson);
        try (PreparedStatement ps = conn.prepareStatement(
                "INSERT INTO events(id, type, branch, root_seq, at_ns, parent_id, payload)"
                        + " VALUES(?, ?, ?, ?, ?, ?, ?)", Statement.RETURN_GENERATED_KEYS)) {
            ps.setString(1, id);
            ps.setString(2, type.name());
            ps.setString(3, branch);
            setLong(ps, 4, rootSeq);
            ps.setLong(5, atNs);
            ps.setString(6, parentId == null ? "" : parentId);
            ps.setString(7, payloadJson);
            ps.executeUpdate();
            long seq;
            try (ResultSet keys = ps.getGeneratedKeys()) {
                keys.next();
                seq = keys.getLong(1);
            }
            return new Event(seq, id, type, branch, rootSeq, atNs,
                    parentId == null ? "" : parentId, payloadJson);
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }

    public List<Event> allEvents() {
        List<Event> out = new ArrayList<>();
        try (Statement st = conn.createStatement();
             ResultSet rs = st.executeQuery(
                     "SELECT seq,id,type,branch,root_seq,at_ns,parent_id,payload FROM events ORDER BY seq")) {
            while (rs.next()) out.add(readEvent(rs));
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
        return out;
    }

    private Event readEvent(ResultSet rs) throws SQLException {
        return new Event(rs.getLong("seq"), rs.getString("id"),
                EventType.valueOf(rs.getString("type")), rs.getString("branch"),
                getLong(rs, "root_seq"), rs.getLong("at_ns"), rs.getString("parent_id"),
                rs.getString("payload"));
    }

    // ---------------------------------------------------------- materials

    public void insertDatagram(Datagram d) {
        try (PreparedStatement ps = conn.prepareStatement(
                "INSERT INTO datagrams(id,t_ns,dir,path_id,bytes_hex,replaced_by)"
                        + " VALUES(?,?,?,?,?,NULL)")) {
            ps.setString(1, d.id());
            ps.setLong(2, d.tNs());
            ps.setString(3, d.dir().name());
            ps.setString(4, d.pathId());
            ps.setString(5, d.bytesHex());
            ps.executeUpdate();
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }

    public void markDatagramReplaced(String id, String replacedBy) {
        try (PreparedStatement ps = conn.prepareStatement(
                "UPDATE datagrams SET replaced_by = ? WHERE id = ?")) {
            ps.setString(1, replacedBy);
            ps.setString(2, id);
            ps.executeUpdate();
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }

    public List<Datagram> allDatagrams() {
        List<Datagram> out = new ArrayList<>();
        try (Statement st = conn.createStatement();
             ResultSet rs = st.executeQuery(
                     "SELECT id,t_ns,dir,path_id,bytes_hex FROM datagrams "
                             + "WHERE replaced_by IS NULL ORDER BY t_ns, id")) {
            while (rs.next()) {
                out.add(new Datagram(rs.getString(1), rs.getLong(2),
                        Direction.valueOf(rs.getString(3)), rs.getString(4), rs.getString(5)));
            }
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }

    public void insertHpCandidate(HpCandidate h) {
        try (PreparedStatement ps = conn.prepareStatement(
                "INSERT INTO hp_candidates(id,packet_id,mask_hex,applied,note) VALUES(?,?,?,?,?)")) {
            ps.setString(1, h.id());
            ps.setString(2, h.packetId());
            ps.setString(3, h.maskHex());
            ps.setInt(4, h.applied() ? 1 : 0);
            ps.setString(5, h.note());
            ps.executeUpdate();
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }

    public List<HpCandidate> allHpCandidates() {
        List<HpCandidate> out = new ArrayList<>();
        try (Statement st = conn.createStatement();
             ResultSet rs = st.executeQuery(
                     "SELECT id,packet_id,mask_hex,applied,note FROM hp_candidates ORDER BY id")) {
            while (rs.next()) {
                out.add(new HpCandidate(rs.getString(1), rs.getString(2), rs.getString(3),
                        rs.getInt(4) == 1, rs.getString(5)));
            }
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
        return out;
    }

    public void insertPacket(Packet p) {
        try (PreparedStatement ps = conn.prepareStatement(
                "INSERT INTO packets(id,datagram_id,offset,space,long_header,version,dcid_hex,"
                        + "scid_hex,key_generation,key_phase_bit,truncated_pn,pn_len,"
                        + "decryptable_gens,ack_frame_hex,raw_header_hex) "
                        + "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)")) {
            ps.setString(1, p.id());
            ps.setString(2, p.datagramId());
            ps.setInt(3, p.offset());
            ps.setString(4, p.space().name());
            ps.setInt(5, p.longHeader() ? 1 : 0);
            ps.setLong(6, p.version());
            ps.setString(7, p.dcidHex());
            ps.setString(8, p.scidHex());
            ps.setLong(9, p.keyGeneration());
            setLong(ps, 10, p.keyPhaseBit() == null ? null : p.keyPhaseBit().longValue());
            ps.setLong(11, p.truncatedPn());
            ps.setInt(12, p.pnLenBytes());
            ps.setString(13, joinLongs(p.decryptableGens()));
            ps.setString(14, p.ackFrameHex());
            ps.setString(15, p.rawHeaderHex());
            ps.executeUpdate();
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }

    public List<Packet> allPackets() {
        List<Packet> out = new ArrayList<>();
        try (Statement st = conn.createStatement();
             ResultSet rs = st.executeQuery(
                     "SELECT id,datagram_id,offset,space,long_header,version,dcid_hex,scid_hex,"
                             + "key_generation,key_phase_bit,truncated_pn,pn_len,"
                             + "decryptable_gens,ack_frame_hex,raw_header_hex FROM packets ORDER BY id")) {
            while (rs.next()) {
                out.add(new Packet(rs.getString(1), rs.getString(2), rs.getInt(3),
                        PnSpace.valueOf(rs.getString(4)), rs.getInt(5) == 1, rs.getLong(6),
                        rs.getString(7), rs.getString(8), rs.getLong(9),
                        (Integer) (rs.getObject(10) == null ? null : rs.getInt(10)),
                        rs.getLong(11), rs.getInt(12), splitLongs(rs.getString(13)),
                        rs.getString(14), rs.getString(15)));
            }
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
        return out;
    }

    private static String joinLongs(List<Long> values) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < values.size(); i++) {
            if (i > 0) sb.append(',');
            sb.append(values.get(i));
        }
        return sb.toString();
    }

    static List<Long> splitLongs(String s) {
        List<Long> out = new ArrayList<>();
        if (s != null && !s.isEmpty()) {
            for (String part : s.split(",")) out.add(Long.parseLong(part));
        }
        return out;
    }

    // ------------------------------------------------------ key/CID/path

    public void insertKeyGen(KeyGen g) {
        try (PreparedStatement ps = conn.prepareStatement(
                "INSERT INTO key_gens(id,role,generation,valid_from_ns,valid_until_ns,secret_label)"
                        + " VALUES(?,?,?,?,?,?)")) {
            ps.setString(1, g.id());
            ps.setString(2, g.role().name());
            ps.setLong(3, g.generation());
            ps.setLong(4, g.validFromNs());
            setLong(ps, 5, g.validUntilNs());
            ps.setString(6, g.secretLabel());
            ps.executeUpdate();
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }

    public List<KeyGen> allKeyGens() {
        List<KeyGen> out = new ArrayList<>();
        try (Statement st = conn.createStatement();
             ResultSet rs = st.executeQuery(
                     "SELECT id,role,generation,valid_from_ns,valid_until_ns,secret_label "
                             + "FROM key_gens ORDER BY role, generation")) {
            while (rs.next()) {
                out.add(new KeyGen(rs.getString(1), KeyRole.valueOf(rs.getString(2)),
                        rs.getLong(3), rs.getLong(4), getLong(rs, "valid_until_ns"),
                        rs.getString(6)));
            }
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
        return out;
    }

    public void insertCidEvent(CidEvent c) {
        try (PreparedStatement ps = conn.prepareStatement(
                "INSERT INTO cid_events(id,seq,cid_hex,issued_ns,retired_ns,issued_on_path_id)"
                        + " VALUES(?,?,?,?,?,?)")) {
            ps.setString(1, c.id());
            ps.setLong(2, c.seq());
            ps.setString(3, c.cidHex());
            ps.setLong(4, c.issuedNs());
            setLong(ps, 5, c.retiredNs());
            ps.setString(6, c.issuedOnPathId());
            ps.executeUpdate();
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }

    public List<CidEvent> allCidEvents() {
        List<CidEvent> out = new ArrayList<>();
        try (Statement st = conn.createStatement();
             ResultSet rs = st.executeQuery(
                     "SELECT id,seq,cid_hex,issued_ns,retired_ns,issued_on_path_id "
                             + "FROM cid_events ORDER BY seq")) {
            while (rs.next()) {
                out.add(new CidEvent(rs.getString(1), rs.getLong(2), rs.getString(3),
                        rs.getLong(4), getLong(rs, "retired_ns"), rs.getString(6)));
            }
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
        return out;
    }

    public void insertPath(PathInfo p) {
        try (PreparedStatement ps = conn.prepareStatement(
                "INSERT INTO paths(id,four_tuple) VALUES(?,?)")) {
            ps.setString(1, p.id());
            ps.setString(2, p.fourTuple());
            ps.executeUpdate();
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }

    public List<PathInfo> allPaths() {
        List<PathInfo> out = new ArrayList<>();
        try (Statement st = conn.createStatement();
             ResultSet rs = st.executeQuery("SELECT id,four_tuple FROM paths ORDER BY id")) {
            while (rs.next()) out.add(new PathInfo(rs.getString(1), rs.getString(2)));
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
        return out;
    }

    // ---------------------------------------------------- decisions/derived

    public void insertDecision(Decision d) {
        try (PreparedStatement ps = conn.prepareStatement(
                "INSERT INTO decisions(id,type,target_id,chosen_value,rationale,author,at_ns,"
                        + "branch,root_seq) VALUES(?,?,?,?,?,?,?,?,?)")) {
            ps.setString(1, d.id());
            ps.setString(2, d.type().name());
            ps.setString(3, d.targetId());
            ps.setString(4, d.chosenValue());
            ps.setString(5, d.rationale());
            ps.setString(6, d.author());
            ps.setLong(7, d.atNs());
            ps.setString(8, d.branch());
            setLong(ps, 9, d.rootSeq());
            ps.executeUpdate();
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }

    public List<Decision> allDecisions() {
        List<Decision> out = new ArrayList<>();
        try (Statement st = conn.createStatement();
             ResultSet rs = st.executeQuery(
                     "SELECT id,type,target_id,chosen_value,rationale,author,at_ns,branch,root_seq "
                             + "FROM decisions ORDER BY at_ns, id")) {
            while (rs.next()) {
                out.add(new Decision(rs.getString(1),
                        Domain.DecisionType.valueOf(rs.getString(2)), rs.getString(3),
                        rs.getString(4), rs.getString(5), rs.getString(6), rs.getLong(7),
                        rs.getString(8), getLong(rs, "root_seq")));
            }
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
        return out;
    }

    public void insertComputation(Computation c) {
        try (PreparedStatement ps = conn.prepareStatement(
                "INSERT INTO computations(id,kind,input_digest,params_version,parent_ids,"
                        + "result_json,invalidated_at_seq,invalid_reason,at_ns,branch,root_seq) "
                        + "VALUES(?,?,?,?,?,?,?,?,?,?,?)")) {
            ps.setString(1, c.id());
            ps.setString(2, c.kind());
            ps.setString(3, c.inputDigest());
            ps.setInt(4, c.paramsVersion());
            ps.setString(5, String.join(",", c.parentIds()));
            ps.setString(6, c.resultJson());
            setLong(ps, 7, c.invalidatedAtSeq());
            ps.setString(8, c.invalidReason());
            ps.setLong(9, c.atNs());
            ps.setString(10, c.branch());
            setLong(ps, 11, c.rootSeq());
            ps.executeUpdate();
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }

    public void invalidateComputations(Iterable<String> ids, long atSeq, String reason) {
        for (String id : ids) {
            try (PreparedStatement ps = conn.prepareStatement(
                    "UPDATE computations SET invalidated_at_seq = ?, invalid_reason = ? "
                            + "WHERE id = ? AND invalidated_at_seq IS NULL")) {
                ps.setLong(1, atSeq);
                ps.setString(2, reason);
                ps.setString(3, id);
                ps.executeUpdate();
            } catch (SQLException e) {
                throw new RuntimeException(e);
            }
        }
    }

    public List<Computation> allComputations() {
        List<Computation> out = new ArrayList<>();
        try (Statement st = conn.createStatement();
             ResultSet rs = st.executeQuery(
                     "SELECT id,kind,input_digest,params_version,parent_ids,result_json,"
                             + "invalidated_at_seq,invalid_reason,at_ns,branch,root_seq "
                             + "FROM computations ORDER BY at_ns, id")) {
            while (rs.next()) {
                out.add(new Computation(rs.getString(1), rs.getString(2), rs.getString(3),
                        rs.getInt(4), List.of(rs.getString(5).split(",", -1)).stream()
                        .filter(s -> !s.isEmpty()).toList(),
                        rs.getString(6), getLong(rs, "invalidated_at_seq"),
                        rs.getString(8), rs.getLong(9), rs.getString(10),
                        getLong(rs, "root_seq")));
            }
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }

    public void wipeAll() {
        tx(() -> {
            for (String table : List.of("computations", "decisions", "cid_events", "key_gens",
                    "packets", "hp_candidates", "datagrams", "paths", "events", "project_meta")) {
                try (Statement st = conn.createStatement()) {
                    st.execute("DELETE FROM " + table);
                }
            }
        });
    }

    @Override
    public void close() {
        try {
            conn.close();
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }
}
