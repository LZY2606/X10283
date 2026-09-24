package quicpn.model;

import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/** Canonical JSON helpers: deterministic serialization and digests. */
public final class Json {
    private static final Gson GSON = new Gson();

    private Json() {}

    public static JsonElement parse(String s) {
        return JsonParser.parseString(s);
    }

    public static JsonObject parseObj(String s) {
        return JsonParser.parseString(s).getAsJsonObject();
    }

    public static String write(JsonElement e) {
        return GSON.toJson(e);
    }

    /** Deterministic serialization: object keys sorted, arrays kept in order. */
    public static String canonical(JsonElement e) {
        StringBuilder sb = new StringBuilder();
        writeCanonical(e, sb);
        return sb.toString();
    }

    private static void writeCanonical(JsonElement e, StringBuilder sb) {
        if (e == null || e.isJsonNull()) {
            sb.append("null");
            return;
        }
        if (e.isJsonObject()) {
            JsonObject o = e.getAsJsonObject();
            List<String> keys = new ArrayList<>(o.keySet());
            Collections.sort(keys);
            sb.append('{');
            boolean first = true;
            for (String k : keys) {
                if (!first) sb.append(',');
                first = false;
                sb.append('"').append(k).append('"').append(':');
                writeCanonical(o.get(k), sb);
            }
            sb.append('}');
        } else if (e.isJsonArray()) {
            sb.append('[');
            boolean first = true;
            for (JsonElement el : e.getAsJsonArray()) {
                if (!first) sb.append(',');
                first = false;
                writeCanonical(el, sb);
            }
            sb.append(']');
        } else {
            sb.append(GSON.toJson(e));
        }
    }

    public static String sha256(String s) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] d = md.digest(s.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (byte b : d) sb.append(String.format("%02x", b));
            return sb.toString();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
