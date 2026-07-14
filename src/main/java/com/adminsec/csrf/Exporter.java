package com.adminsec.csrf;

import com.google.gson.GsonBuilder;
import com.adminsec.csrf.model.Candidate;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;

public final class Exporter {
    public void export(Path path, List<Candidate> candidates) throws IOException {
        export(path, candidates, true);
    }
    public void export(Path path, List<Candidate> candidates, boolean includeNotes) throws IOException {
        String name = path.getFileName().toString().toLowerCase(Locale.ROOT);
        String content = name.endsWith(".csv") ? csv(candidates, includeNotes)
                : name.endsWith(".html") || name.endsWith(".htm") ? html(candidates, includeNotes)
                : json(candidates, includeNotes);
        Files.writeString(path, content, StandardCharsets.UTF_8);
    }
    String json(List<Candidate> candidates) {
        return json(candidates, true);
    }
    String json(List<Candidate> candidates, boolean includeNotes) {
        return new GsonBuilder().setPrettyPrinting().create().toJson(candidates.stream().map(candidate -> row(candidate, includeNotes)).toList());
    }
    String csv(List<Candidate> candidates) {
        return csv(candidates, true);
    }
    String csv(List<Candidate> candidates, boolean includeNotes) {
        StringBuilder out = new StringBuilder("endpoint,action,priority,confidence,authentication,token,origin,fetch_metadata,cors,cookie_defense,exploitability,status,occurrences,first_seen,last_seen");
        if (includeNotes) out.append(",note");
        out.append('\n');
        for (Candidate candidate : candidates) {
            Map<String, String> row = row(candidate, includeNotes);
            out.append(String.join(",", row.values().stream().map(Exporter::quote).toList())).append('\n');
        }
        return out.toString();
    }
    String html(List<Candidate> candidates) {
        return html(candidates, true);
    }
    String html(List<Candidate> candidates, boolean includeNotes) {
        StringBuilder out = new StringBuilder("<!doctype html><meta charset=\"utf-8\"><meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'\"><title>CSRF Review Assistant report</title>")
                .append("<style>body{font-family:sans-serif;margin:2rem}table{border-collapse:collapse;width:100%}th,td{border:1px solid #bbb;padding:.4rem;text-align:left}th{background:#eee}</style>")
                .append("<h1>CSRF Review Assistant</h1><p>Passive candidates only. Manual verification is required.</p><table><thead><tr>");
        List<String> columns = new ArrayList<>(List.of("endpoint", "action", "priority", "confidence", "authentication", "token", "origin",
                "fetchMetadata", "cors", "cookieDefense", "exploitability", "status", "occurrences", "firstSeen", "lastSeen"));
        if (includeNotes) columns.add("note");
        columns.forEach(column -> out.append("<th>").append(escape(column)).append("</th>")); out.append("</tr></thead><tbody>");
        for (Candidate candidate : candidates) { Map<String, String> row = row(candidate, includeNotes); out.append("<tr>"); row.values().forEach(v -> out.append("<td>").append(escape(v)).append("</td>")); out.append("</tr>"); }
        return out.append("</tbody></table>").toString();
    }
    private Map<String, String> row(Candidate candidate, boolean includeNotes) {
        var a = candidate.assessment(); Map<String, String> row = new LinkedHashMap<>();
        row.put("endpoint", a.endpointKey()); row.put("action", a.actionType()); row.put("priority", a.priority().label());
        row.put("confidence", a.confidence()); row.put("authentication", a.authEvidence()); row.put("token", a.tokenEvidence());
        row.put("origin", a.originEvidence()); row.put("fetchMetadata", a.fetchMetadataEvidence()); row.put("cors", a.corsEvidence());
        row.put("cookieDefense", a.cookieDefense()); row.put("exploitability", a.exploitability()); row.put("status", candidate.status().label());
        row.put("occurrences", Long.toString(candidate.occurrences())); row.put("firstSeen", candidate.firstSeen().toString()); row.put("lastSeen", candidate.lastSeen().toString());
        if (includeNotes) row.put("note", candidate.note());
        row.replaceAll((key, value) -> Redaction.redact(value)); return row;
    }
    private static String quote(String value) {
        String safe = value == null ? "" : value;
        String trimmed = safe.stripLeading();
        if (!trimmed.isEmpty() && "=+-@".indexOf(trimmed.charAt(0)) >= 0) safe = "'" + safe;
        return "\"" + safe.replace("\"", "\"\"") + "\"";
    }
    private static String escape(String value) { return value == null ? "" : value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;"); }
}
