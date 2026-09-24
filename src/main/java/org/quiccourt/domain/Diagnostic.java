package org.quiccourt.domain;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/** A located diagnostic. {@code location} uses JSON-ish paths, never null on errors. */
public final class Diagnostic {
    private final Severity severity;
    private final DiagClass category;
    private final String code;
    private final String message;
    private final String location;
    private final String evidence;
    private final List<String> affectedObjectIds;

    public Diagnostic(Severity severity, DiagClass category, String code, String message,
                      String location, String evidence, List<String> affectedObjectIds) {
        this.severity = severity;
        this.category = category;
        this.code = code;
        this.message = message;
        this.location = location;
        this.evidence = evidence;
        this.affectedObjectIds = affectedObjectIds == null
                ? Collections.emptyList() : List.copyOf(affectedObjectIds);
    }

    public static Diagnostic error(DiagClass cat, String code, String message, String location,
                                   String evidence, List<String> affected) {
        return new Diagnostic(Severity.ERROR, cat, code, message, location, evidence, affected);
    }

    public static Diagnostic warning(String code, String message, String location, String evidence) {
        return new Diagnostic(Severity.WARNING, null, code, message, location, evidence, new ArrayList<>());
    }

    public static Diagnostic info(String code, String message, String location) {
        return new Diagnostic(Severity.INFO, null, code, message, location, null, new ArrayList<>());
    }

    public Severity severity() {
        return severity;
    }

    public DiagClass category() {
        return category;
    }

    public String code() {
        return code;
    }

    public String message() {
        return message;
    }

    public String location() {
        return location;
    }

    public String evidence() {
        return evidence;
    }

    public List<String> affectedObjectIds() {
        return affectedObjectIds;
    }
}
