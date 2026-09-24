package quicpn.model;

import com.google.gson.JsonObject;

/** A positioned diagnostic: never a silent default. */
public record Diagnostic(String position, String code, String message) {
    public JsonObject toJson() {
        JsonObject o = new JsonObject();
        o.addProperty("position", position);
        o.addProperty("code", code);
        o.addProperty("message", message);
        return o;
    }

    public static Diagnostic fromJson(JsonObject o) {
        return new Diagnostic(
                o.get("position").getAsString(),
                o.get("code").getAsString(),
                o.get("message").getAsString());
    }
}
