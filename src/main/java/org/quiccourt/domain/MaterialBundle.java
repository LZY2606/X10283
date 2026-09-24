package org.quiccourt.domain;

import java.util.List;

/** One immutable import package plus any non-fatal diagnostics. */
public final class MaterialBundle {
    public final String label;
    public final String captureBasis;
    public final List<Material.Datagram> datagrams;
    public final List<Material.Header> headers;
    public final List<Material.HpCandidate> hpCandidates;
    public final List<Material.DecryptionCandidate> decryptionCandidates;
    public final List<Material.CidEvent> cidEvents;
    public final List<Material.PathInfo> paths;
    public final List<Material.AckRange> ackRanges;
    public final List<Diagnostic> warnings;

    public MaterialBundle(String label, String captureBasis,
                          List<Material.Datagram> datagrams,
                          List<Material.Header> headers,
                          List<Material.HpCandidate> hpCandidates,
                          List<Material.DecryptionCandidate> decryptionCandidates,
                          List<Material.CidEvent> cidEvents,
                          List<Material.PathInfo> paths,
                          List<Material.AckRange> ackRanges,
                          List<Diagnostic> warnings) {
        this.label = label;
        this.captureBasis = captureBasis;
        this.datagrams = List.copyOf(datagrams);
        this.headers = List.copyOf(headers);
        this.hpCandidates = List.copyOf(hpCandidates);
        this.decryptionCandidates = List.copyOf(decryptionCandidates);
        this.cidEvents = List.copyOf(cidEvents);
        this.paths = List.copyOf(paths);
        this.ackRanges = List.copyOf(ackRanges);
        this.warnings = List.copyOf(warnings);
    }
}
