package gsb.quic.court.domain;

/**
 * Immutable source material. {@code rawJson} is the exact imported representation
 * (never rewritten). {@code kind} selects the typed view in {@code payload}.
 *
 * @param id stable identity, assigned by the import manifest and preserved across export/import
 * @param kind material vocabulary
 * @param originProvenance free-form text identifying the capture/source
 * @param payload typed view used by the derivation layer
 * @param rawJson exact original JSON text as imported
 */
public record Material(String id, MaterialKind kind, String originProvenance,
                       java.util.Map<String, Object> payload, String rawJson) {

    public String str(String key) {
        Object v = payload.get(key);
        return v == null ? null : v.toString();
    }

    public Long integer(String key) {
        Object v = payload.get(key);
        if (v == null) {
            return null;
        }
        if (v instanceof Number n) {
            return n.longValue();
        }
        return Long.parseLong(v.toString().trim());
    }
}
