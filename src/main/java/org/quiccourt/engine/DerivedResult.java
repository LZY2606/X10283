package org.quiccourt.engine;

import java.util.List;

/**
 * A derived, content-addressed object. Records input summary, parameter/rule
 * version and parent dependencies so any value can be traced back to material,
 * rule version and decision.
 */
public final class DerivedResult {
    public final String stableId;
    public final ResultKind kind;
    public final ResultStatus status;
    public final String targetObjectId;
    public final String space;
    public final String direction;
    public final List<Candidate> candidates;
    public final String detailsJson;
    public final String inputSummary;
    public final int paramsVersion;
    public final String ruleVersion;
    public final List<String> parentDependencies;
    public final String producedByEventId;
    public final int branchSeq;
    public final boolean adopted;
    public final String humanVerdict;
    public final boolean conflictWithEngine;

    public DerivedResult(String stableId, ResultKind kind, ResultStatus status, String targetObjectId,
                         String space, String direction, List<Candidate> candidates, String detailsJson,
                         String inputSummary, int paramsVersion, String ruleVersion,
                         List<String> parentDependencies, String producedByEventId, int branchSeq,
                         boolean adopted, String humanVerdict, boolean conflictWithEngine) {
        this.stableId = stableId;
        this.kind = kind;
        this.status = status;
        this.targetObjectId = targetObjectId;
        this.space = space;
        this.direction = direction;
        this.candidates = candidates;
        this.detailsJson = detailsJson;
        this.inputSummary = inputSummary;
        this.paramsVersion = paramsVersion;
        this.ruleVersion = ruleVersion;
        this.parentDependencies = parentDependencies;
        this.producedByEventId = producedByEventId;
        this.branchSeq = branchSeq;
        this.adopted = adopted;
        this.humanVerdict = humanVerdict;
        this.conflictWithEngine = conflictWithEngine;
    }

    public DerivedResult withAdoption(boolean newAdopted, String humanVerdict, boolean conflict) {
        return new DerivedResult(stableId, kind, status, targetObjectId, space, direction, candidates,
                detailsJson, inputSummary, paramsVersion, ruleVersion, parentDependencies,
                producedByEventId, branchSeq, newAdopted, humanVerdict, conflict);
    }

    public DerivedResult atSeq(int newSeq) {
        return new DerivedResult(stableId, kind, status, targetObjectId, space, direction, candidates,
                detailsJson, inputSummary, paramsVersion, ruleVersion, parentDependencies,
                producedByEventId, newSeq, adopted, humanVerdict, conflictWithEngine);
    }
}
