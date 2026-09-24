package quicpn.model;

import com.google.gson.JsonObject;

/**
 * Immutable evidentiary material: raw datagram bytes, truncated packet numbers,
 * header-protection candidates, key generations, CID events, paths, ACK ranges.
 * Amendments never edit a material in place; they supersede it via events.
 */
public record Material(String id, long seq, String kind, JsonObject payload, String digest) {

    public static Material of(String id, long seq, String kind, JsonObject payload) {
        return new Material(id, seq, kind, payload, Json.sha256(Json.canonical(payload)));
    }

    public JsonObject toJson() {
        JsonObject o = new JsonObject();
        o.addProperty("id", id);
        o.addProperty("seq", seq);
        o.addProperty("kind", kind);
        o.add("payload", payload);
        o.addProperty("digest", digest);
        return o;
    }

    public static Material fromJson(JsonObject o) {
        return new Material(
                o.get("id").getAsString(),
                o.get("seq").getAsLong(),
                o.get("kind").getAsString(),
                o.getAsJsonObject("payload"),
                o.get("digest").getAsString());
    }
}
