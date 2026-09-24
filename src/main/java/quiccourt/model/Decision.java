package quiccourt.model;

import com.fasterxml.jackson.databind.JsonNode;

/** A mutable-layer human decision. Never edits materials; supersedes earlier decisions. */
public record Decision(
        String id,
        String caseId,
        String branch,
        long seq,
        String kind,          // ACCEPT | REJECT | PARAM_ADJUST
        String targetId,      // material / derived / candidate id the decision applies to
        JsonNode payload,     // rationale, parameter values, chosen candidate ...
        String supersedes,    // nullable: id of the decision this one replaces
        String introducedByEvent
) {}
