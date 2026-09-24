package quicpn.model;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import java.util.ArrayList;
import java.util.List;

/**
 * An append-only event: imports, computations, parameter revisions, source
 * amendments and human decisions. Every event records its input digest,
 * parameter version and parent dependencies so history is replayable.
 */
public record Event(
        String id,
        long seq,
        String kind,
        String branch,
        String inputDigest,
        String paramVersion,
        List<String> parents,
        JsonObject payload) {

    public JsonObject toJson() {
        JsonObject o = new JsonObject();
        o.addProperty("id", id);
        o.addProperty("seq", seq);
        o.addProperty("kind", kind);
        o.addProperty("branch", branch);
        o.addProperty("input_digest", inputDigest);
        o.addProperty("param_version", paramVersion);
        JsonArray p = new JsonArray();
        for (String parent : parents) p.add(parent);
        o.add("parents", p);
        o.add("payload", payload);
        return o;
    }

    public static Event fromJson(JsonObject o) {
        List<String> parents = new ArrayList<>();
        for (var el : o.getAsJsonArray("parents")) parents.add(el.getAsString());
        return new Event(
                o.get("id").getAsString(),
                o.get("seq").getAsLong(),
                o.get("kind").getAsString(),
                o.get("branch").getAsString(),
                o.get("input_digest").getAsString(),
                o.get("param_version").getAsString(),
                parents,
                o.getAsJsonObject("payload"));
    }
}
