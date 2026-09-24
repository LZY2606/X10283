package quicpn.engine;

import java.util.ArrayList;
import java.util.List;
import quicpn.model.Diagnostic;
import quicpn.model.Outcome;

/**
 * Key-phase state machine. A phase flip is only committed after the packet
 * decrypts successfully AND a confirmation rule fires (peer ACK confirmation
 * or a subsequent decryptable packet in the new phase). Until then candidates
 * stay pending; failed decryptions become explicit gaps, never silent drops.
 * Superseded keys remain usable inside a grace window.
 */
public final class KeyPhaseTracker {

    public enum Status {
        ACCEPTED,
        GRACE_OLD_KEY,
        COMMITTED_KEY_UPDATE,
        PENDING_CANDIDATE,
        REJECTED_FALSE_FLIP,
        REJECTED_GRACE_EXPIRED,
        GAP_UNDECRYPTABLE
    }

    public record PacketIn(
            int index,
            Long pn,
            boolean keyPhase,
            int keyGeneration,
            boolean decryptOk,
            boolean ackConfirmed,
            long timeMs) {}

    public record Verdict(PacketIn packet, Status status, int generation, String reason) {}

    public record State(
            boolean committedPhase,
            int generation,
            List<Verdict> verdicts,
            List<Diagnostic> diagnostics,
            Outcome outcome) {}

    private KeyPhaseTracker() {}

    public static State track(List<PacketIn> packets, int gracePackets) {
        List<Verdict> verdicts = new ArrayList<>();
        List<Diagnostic> diags = new ArrayList<>();
        boolean phase = false;
        int generation = 0;
        int commitIndex = -1;
        for (int i = 0; i < packets.size(); i++) {
            PacketIn p = packets.get(i);
            if (!p.decryptOk()) {
                if (p.keyPhase() != phase) {
                    verdicts.add(new Verdict(p, Status.REJECTED_FALSE_FLIP, generation,
                            "key phase 误翻转：新相位包解密失败，不提交翻转"));
                    diags.add(new Diagnostic("packets[" + p.index() + "]", "keyphase.false-flip",
                            "t=" + p.timeMs() + "ms 相位=" + (p.keyPhase() ? 1 : 0) + " 解密失败，判定误翻转"));
                } else {
                    verdicts.add(new Verdict(p, Status.GAP_UNDECRYPTABLE, generation,
                            "无法解密空洞：当前密钥无法解密，保留空洞待后续密钥代次回填"));
                    diags.add(new Diagnostic("packets[" + p.index() + "]", "decrypt.gap",
                            "t=" + p.timeMs() + "ms 无法解密，形成空洞"));
                }
                continue;
            }
            if (p.keyGeneration() == generation && p.keyPhase() == phase) {
                verdicts.add(new Verdict(p, Status.ACCEPTED, generation, "当前密钥代次解密成功"));
                continue;
            }
            if (p.keyGeneration() < generation) {
                boolean withinGrace = commitIndex >= 0 && (i - commitIndex) <= gracePackets;
                if (withinGrace) {
                    verdicts.add(new Verdict(p, Status.GRACE_OLD_KEY, p.keyGeneration(),
                            "旧密钥宽限内接受（宽限 " + gracePackets + " 包）"));
                } else {
                    verdicts.add(new Verdict(p, Status.REJECTED_GRACE_EXPIRED, p.keyGeneration(),
                            "旧密钥宽限已过，拒绝"));
                    diags.add(new Diagnostic("packets[" + p.index() + "]", "keyphase.grace-expired",
                            "t=" + p.timeMs() + "ms 旧代次 gen=" + p.keyGeneration() + " 超出宽限"));
                }
                continue;
            }
            // Newer generation / flipped phase: commit only on confirmation.
            boolean confirmed = p.ackConfirmed() || subsequentConfirms(packets, i, p.keyPhase(), p.keyGeneration());
            if (confirmed) {
                phase = p.keyPhase();
                generation = p.keyGeneration();
                commitIndex = i;
                verdicts.add(new Verdict(p, Status.COMMITTED_KEY_UPDATE, generation,
                        "解密成功且确认规则满足，提交 key update 至 gen=" + generation));
            } else {
                verdicts.add(new Verdict(p, Status.PENDING_CANDIDATE, generation,
                        "候选翻转：解密成功但缺少确认，保留候选不提交"));
                diags.add(new Diagnostic("packets[" + p.index() + "]", "keyphase.pending",
                        "t=" + p.timeMs() + "ms 候选翻转未确认，保持 gen=" + generation));
            }
        }
        return new State(phase, generation, verdicts, diags, Outcome.OK);
    }

    private static boolean subsequentConfirms(List<PacketIn> packets, int i, boolean phase, int gen) {
        for (int j = i + 1; j < packets.size(); j++) {
            PacketIn q = packets.get(j);
            if (q.keyPhase() == phase && q.keyGeneration() == gen && q.decryptOk()) return true;
        }
        return false;
    }
}
