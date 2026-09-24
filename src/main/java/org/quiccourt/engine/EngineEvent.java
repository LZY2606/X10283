package org.quiccourt.engine;

import java.util.List;

/**
 * An append-only, replayable event. The {@code payload} is canonical JSON.
 * Rejected imports are also events so their input fragment, judgement and
 * affected objects survive in the record.
 */
public final class EngineEvent {
    public final String id;
    public final int seq;
    public final EventType type;
    public final String branchId;
    public final String parentEventId;
    public final long wallOrder;
    public final String payloadJson;
    public final String label;

    public EngineEvent(String id, int seq, EventType type, String branchId, String parentEventId,
                       long wallOrder, String payloadJson, String label) {
        this.id = id;
        this.seq = seq;
        this.type = type;
        this.branchId = branchId;
        this.parentEventId = parentEventId;
        this.wallOrder = wallOrder;
        this.payloadJson = payloadJson;
        this.label = label;
    }

    /** Material ids introduced (or amended) by this event, for dependency tracking. */
    public List<String> touchedMaterialIds() {
        return EventPayloads.touchedMaterialIds(payloadJson);
    }
}
