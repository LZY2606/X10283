package quiccourt;

import java.util.LinkedHashMap;
import java.util.Map;

/** A positioned diagnostic. Never silently dropped; raw values stay in place. */
public record Diag(String position, String code, String message) {
    public Map<String, Object> toMap() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("position", position);
        m.put("code", code);
        m.put("message", message);
        return m;
    }

    public static Diag fromJson(com.fasterxml.jackson.databind.JsonNode n) {
        return new Diag(n.get("position").asText(), n.get("code").asText(), n.get("message").asText());
    }
}
