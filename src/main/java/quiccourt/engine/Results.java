package quiccourt.engine;

import quiccourt.model.Diagnostic;
import java.util.List;
import java.util.Map;

/** Derived-layer computation outputs. Every value carries unit / coordinate basis. */
public final class Results {

    public record PacketEntry(String packetId, String datagramId, String pnSpace,
                              Long timeUs, String timeBasis, String direction, String pathId,
                              Long truncatedPn, List<Long> candidates, Long rfcPreferred,
                              Long chosen, Long windowLo, Long windowHi,
                              String status, String failureKind, String invalidReason,
                              String unit) {}

    public record PnSpaceState(String space, long expectedNext, List<PacketEntry> entries,
                               String unit, String basis) {}

    public record KeyPhaseEvent(String packetId, Long timeUs, Integer phaseBit, long keyGen,
                                String action, String reason, long committedGen,
                                int committedPhase, int graceRemaining) {}

    public record KeyPhaseTrace(List<KeyPhaseEvent> events, long currentGen, int currentPhase,
                                int pendingConfirm, String unit, String basis) {}

    public record CidNode(String cidHex, long sequence, String state, List<String> eventIds) {}
    public record CidEdge(String fromCid, String toCid, String pathId, String eventId, Long timeUs) {}
    public record CidLineage(List<CidNode> nodes, List<CidEdge> edges) {}

    public record PathInterval(String pathId, Long startUs, Long endUs, String state,
                               String invalidReason, String tuple) {}
    public record PathPacket(String packetId, Long timeUs, String direction) {}
    public record PathLane(String pathId, String tuple, List<PathInterval> intervals,
                           List<PathPacket> packets) {}
    public record PathTimeline(List<PathLane> lanes, List<String> migrations,
                               String unit, String basis) {}

    public record MergedRange(long start, long end, List<String> sourceIds) {}
    public record AckMerge(String space, List<MergedRange> ranges, long largestAcked,
                           String unit) {}

    public record Run(PnSpaceState initial, PnSpaceState handshake, PnSpaceState application,
                      KeyPhaseTrace keyPhase, CidLineage cidLineage, PathTimeline paths,
                      Map<String, AckMerge> acks, List<Diagnostic> diagnostics,
                      String paramsVersion, String inputDigest) {}
}
