package quicpn.model;

import com.google.gson.JsonObject;

/**
 * A derived (computed) result. Carries the producing event, the event-seq at
 * which it was created and (if superseded) the event-seq at which it was
 * invalidated plus the reason, so any historical viewpoint can be restored.
 */
public record Derived(
        String id,
        long seq,
        String kind,
        String eventId,
        long createdSeq,
        Long invalidatedSeq,
        String invalidReason,
        JsonObject payload) {

    public boolean visibleAsOf(long asOfSeq) {
        if (createdSeq > asOfSeq) return false;
        return invalidatedSeq == null || invalidatedSeq > asOfSeq;
    }

    public JsonObject toJson() {
        JsonObject o = new JsonObject();
        o.addProperty("id", id);
        o.addProperty("seq", seq);
        o.addProperty("kind", kind);
        o.addProperty("event_id", eventId);
        o.addProperty("created_seq", createdSeq);
        if (invalidatedSeq != null) o.addProperty("invalidated_seq", invalidatedSeq);
        if (invalidReason != null) o.addProperty("invalid_reason", invalidReason);
        o.add("payload", payload);
        return o;
    }

    public static Derived fromJson(JsonObject o) {
        return new Derived(
                o.get("id").getAsString(),
                o.get("seq").getAsLong(),
                o.get("kind").getAsString(),
                o.get("event_id").getAsString(),
                o.get("created_seq").getAsLong(),
                o.has("invalidated_seq") ? o.get("invalidated_seq").getAsLong() : null,
                o.has("invalid_reason") ? o.get("invalid_reason").getAsString() : null,
                o.getAsJsonObject("payload"));
    }
}
