package quicpn.db;

import com.google.gson.JsonObject;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import quicpn.model.Derived;
import quicpn.model.Event;
import quicpn.model.Json;
import quicpn.model.Material;

/**
 * SQLite-backed store. Materials are immutable; events are append-only;
 * derived rows are invalidated (never deleted) so history stays replayable.
 */
public final class Database implements AutoCloseable {
    private final Connection conn;

    public Database(Path path) {
        this(open("jdbc:sqlite:" + path.toAbsolutePath()));
    }

    public static Database inMemory() {
        return new Database(open("jdbc:sqlite::memory:"));
    }

    private Database(Connection c) {
        this.conn = c;
        migrate();
    }

    private static Connection open(String url) {
        try {
            Connection c = DriverManager.getConnection(url);
            try (Statement s = c.createStatement()) {
                s.execute("PRAGMA journal_mode=WAL");
                s.execute("PRAGMA foreign_keys=ON");
            }
            return c;
        } catch (SQLException e) {
            throw new IllegalStateException("cannot open database: " + url, e);
        }
    }

    private void migrate() {
        try (Statement s = conn.createStatement()) {
            s.execute("CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)");
            s.execute("CREATE TABLE IF NOT EXISTS materials ("
                    + "id TEXT PRIMARY KEY, seq INTEGER NOT NULL, kind TEXT NOT NULL,"
                    + " payload TEXT NOT NULL, digest TEXT NOT NULL)");
            s.execute("CREATE TABLE IF NOT EXISTS events ("
                    + "id TEXT PRIMARY KEY, seq INTEGER NOT NULL, kind TEXT NOT NULL, branch TEXT NOT NULL,"
                    + " input_digest TEXT NOT NULL, param_version TEXT NOT NULL, parents TEXT NOT NULL,"
                    + " payload TEXT NOT NULL)");
            s.execute("CREATE TABLE IF NOT EXISTS derived ("
                    + "id TEXT PRIMARY KEY, seq INTEGER NOT NULL, kind TEXT NOT NULL, event_id TEXT NOT NULL,"
                    + " created_seq INTEGER NOT NULL, invalidated_seq INTEGER, invalid_reason TEXT,"
                    + " payload TEXT NOT NULL)");
        } catch (SQLException e) {
            throw new IllegalStateException("migration failed", e);
        }
    }

    public String meta(String key, String def) {
        try (PreparedStatement ps = conn.prepareStatement("SELECT value FROM meta WHERE key=?")) {
            ps.setString(1, key);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next() ? rs.getString(1) : def;
            }
        } catch (SQLException e) {
            throw new IllegalStateException(e);
        }
    }

    public void setMeta(String key, String value) {
        try (PreparedStatement ps = conn.prepareStatement(
                "INSERT INTO meta(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value")) {
            ps.setString(1, key);
            ps.setString(2, value);
            ps.executeUpdate();
        } catch (SQLException e) {
            throw new IllegalStateException(e);
        }
    }

    public void insertMaterial(Material m) {
        try (PreparedStatement ps = conn.prepareStatement(
                "INSERT INTO materials(id,seq,kind,payload,digest) VALUES(?,?,?,?,?)")) {
            ps.setString(1, m.id());
            ps.setLong(2, m.seq());
            ps.setString(3, m.kind());
            ps.setString(4, Json.write(m.payload()));
            ps.setString(5, m.digest());
            ps.executeUpdate();
        } catch (SQLException e) {
            throw new IllegalStateException("insert material " + m.id(), e);
        }
    }

    public Optional<Material> material(String id) {
        return materials().stream().filter(m -> m.id().equals(id)).findFirst();
    }

    public List<Material> materials() {
        List<Material> out = new ArrayList<>();
        try (PreparedStatement ps = conn.prepareStatement("SELECT * FROM materials ORDER BY seq, id");
                ResultSet rs = ps.executeQuery()) {
            while (rs.next()) out.add(readMaterial(rs));
        } catch (SQLException e) {
            throw new IllegalStateException(e);
        }
        return out;
    }

    public List<Material> materials(String kind) {
        List<Material> out = new ArrayList<>();
        for (Material m : materials()) if (m.kind().equals(kind)) out.add(m);
        return out;
    }

    private static Material readMaterial(ResultSet rs) throws SQLException {
        return new Material(
                rs.getString("id"),
                rs.getLong("seq"),
                rs.getString("kind"),
                Json.parseObj(rs.getString("payload")),
                rs.getString("digest"));
    }

    public long nextEventSeq() {
        return meta("seq.event", "0").isEmpty() ? 1 : Long.parseLong(meta("seq.event", "0")) + 1;
    }

    public String newEventId() {
        long seq = nextEventSeq();
        setMeta("seq.event", Long.toString(seq));
        return "evt-" + String.format("%04d", seq);
    }

    public void insertEvent(Event e) {
        try (PreparedStatement ps = conn.prepareStatement(
                "INSERT INTO events(id,seq,kind,branch,input_digest,param_version,parents,payload)"
                        + " VALUES(?,?,?,?,?,?,?,?)")) {
            ps.setString(1, e.id());
            ps.setLong(2, e.seq());
            ps.setString(3, e.kind());
            ps.setString(4, e.branch());
            ps.setString(5, e.inputDigest());
            ps.setString(6, e.paramVersion());
            ps.setString(7, Json.write(toJsonArray(e.parents())));
            ps.setString(8, Json.write(e.payload()));
            ps.executeUpdate();
        } catch (SQLException ex) {
            throw new IllegalStateException("insert event " + e.id(), ex);
        }
    }

    private static com.google.gson.JsonArray toJsonArray(List<String> items) {
        com.google.gson.JsonArray a = new com.google.gson.JsonArray();
        for (String s : items) a.add(s);
        return a;
    }

    public List<Event> events() {
        List<Event> out = new ArrayList<>();
        try (PreparedStatement ps = conn.prepareStatement("SELECT * FROM events ORDER BY seq, id");
                ResultSet rs = ps.executeQuery()) {
            while (rs.next()) {
                List<String> parents = new ArrayList<>();
                for (var el : Json.parse(rs.getString("parents")).getAsJsonArray())
                    parents.add(el.getAsString());
                out.add(new Event(
                        rs.getString("id"),
                        rs.getLong("seq"),
                        rs.getString("kind"),
                        rs.getString("branch"),
                        rs.getString("input_digest"),
                        rs.getString("param_version"),
                        parents,
                        Json.parseObj(rs.getString("payload"))));
            }
        } catch (SQLException e) {
            throw new IllegalStateException(e);
        }
        return out;
    }

    public Optional<Event> event(String id) {
        return events().stream().filter(e -> e.id().equals(id)).findFirst();
    }

    public String newDerivedId() {
        long seq = Long.parseLong(meta("seq.derived", "0")) + 1;
        setMeta("seq.derived", Long.toString(seq));
        return "drv-" + String.format("%04d", seq);
    }

    public void insertDerived(Derived d) {
        try (PreparedStatement ps = conn.prepareStatement(
                "INSERT INTO derived(id,seq,kind,event_id,created_seq,invalidated_seq,invalid_reason,payload)"
                        + " VALUES(?,?,?,?,?,?,?,?)")) {
            ps.setString(1, d.id());
            ps.setLong(2, d.seq());
            ps.setString(3, d.kind());
            ps.setString(4, d.eventId());
            ps.setLong(5, d.createdSeq());
            if (d.invalidatedSeq() != null) ps.setLong(6, d.invalidatedSeq()); else ps.setNull(6, java.sql.Types.INTEGER);
            if (d.invalidReason() != null) ps.setString(7, d.invalidReason()); else ps.setNull(7, java.sql.Types.VARCHAR);
            ps.setString(8, Json.write(d.payload()));
            ps.executeUpdate();
        } catch (SQLException e) {
            throw new IllegalStateException("insert derived " + d.id(), e);
        }
    }

    public List<Derived> derived() {
        List<Derived> out = new ArrayList<>();
        try (PreparedStatement ps = conn.prepareStatement("SELECT * FROM derived ORDER BY seq, id");
                ResultSet rs = ps.executeQuery()) {
            while (rs.next()) {
                Long invalidated = rs.getObject("invalidated_seq") == null ? null : rs.getLong("invalidated_seq");
                out.add(new Derived(
                        rs.getString("id"),
                        rs.getLong("seq"),
                        rs.getString("kind"),
                        rs.getString("event_id"),
                        rs.getLong("created_seq"),
                        invalidated,
                        rs.getString("invalid_reason"),
                        Json.parseObj(rs.getString("payload"))));
            }
        } catch (SQLException e) {
            throw new IllegalStateException(e);
        }
        return out;
    }

    public List<Derived> derived(String kind) {
        List<Derived> out = new ArrayList<>();
        for (Derived d : derived()) if (d.kind().equals(kind)) out.add(d);
        return out;
    }

    public void invalidateDerived(String id, long atEventSeq, String reason) {
        try (PreparedStatement ps = conn.prepareStatement(
                "UPDATE derived SET invalidated_seq=?, invalid_reason=? WHERE id=? AND invalidated_seq IS NULL")) {
            ps.setLong(1, atEventSeq);
            ps.setString(2, reason);
            ps.setString(3, id);
            ps.executeUpdate();
        } catch (SQLException e) {
            throw new IllegalStateException(e);
        }
    }

    public long count(String table) {
        try (Statement s = conn.createStatement();
                ResultSet rs = s.executeQuery("SELECT COUNT(*) FROM " + table)) {
            rs.next();
            return rs.getLong(1);
        } catch (SQLException e) {
            throw new IllegalStateException(e);
        }
    }

    /** Removes all rows; used by archive import after validation succeeds. */
    public void wipe() {
        try (Statement s = conn.createStatement()) {
            s.execute("DELETE FROM derived");
            s.execute("DELETE FROM events");
            s.execute("DELETE FROM materials");
            s.execute("DELETE FROM meta");
        } catch (SQLException e) {
            throw new IllegalStateException(e);
        }
    }

    /** Canonical snapshot used by round-trip comparisons. */
    public String snapshot() {
        JsonObject o = new JsonObject();
        com.google.gson.JsonArray mats = new com.google.gson.JsonArray();
        for (Material m : materials()) mats.add(m.toJson());
        com.google.gson.JsonArray evs = new com.google.gson.JsonArray();
        for (Event e : events()) evs.add(e.toJson());
        com.google.gson.JsonArray drvs = new com.google.gson.JsonArray();
        for (Derived d : derived()) drvs.add(d.toJson());
        o.add("materials", mats);
        o.add("events", evs);
        o.add("derived", drvs);
        return Json.canonical(o);
    }

    @Override
    public void close() {
        try {
            conn.close();
        } catch (SQLException e) {
            throw new IllegalStateException(e);
        }
    }
}
