package quiccourt.model;

import com.fasterxml.jackson.databind.JsonNode;

/** One immutable piece of evidence. rawJson keeps the original representation
 *  (units, coordinate bases) exactly as imported; derived layers normalise. */
public record Material(
        String id,
        String caseId,
        String branch,
        long seq,            // stable order within the case
        MaterialKind kind,
        JsonNode raw,
        String digest,
        String introducedByEvent
) {}
