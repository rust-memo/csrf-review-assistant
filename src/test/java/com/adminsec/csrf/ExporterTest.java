package com.adminsec.csrf;

import com.adminsec.csrf.model.*;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class ExporterTest {
    @Test void exportContainsEvidenceButNoRawSecretValues() {
        Assessment assessment = new Assessment("example.test|POST|/account", "Sensitive", "Likely session cookie: session", true,
                "CSRF token observed in BODY: csrf_token (validation unverified)", "csrf_token", "Origin absent", "SameSite unknown",
                "Browser-forgeable", Priority.PROTECTED, "Medium", List.of());
        Candidate candidate = new Candidate("key", assessment, null, ReviewStatus.NEW, "Authorization: Bearer super-secret-cookie-value\ncsrf_token=raw-secret");
        String json = new Exporter().json(List.of(candidate));
        assertTrue(json.contains("csrf_token"));
        assertFalse(json.contains("super-secret-cookie-value"));
        assertFalse(json.contains("Bearer"));
        assertFalse(json.contains("raw-secret"));
        assertTrue(json.contains("REDACTED"));
    }

    @Test void csvProtectsSpreadsheetFormulaCells() {
        Assessment assessment = new Assessment("=HYPERLINK(\"https://example.test\")", "Sensitive", "Cookie", true,
                "No token", "", "Origin absent", "SameSite unknown", "Browser-forgeable",
                Priority.REVIEW_1, "High", List.of());
        Candidate candidate = new Candidate("key", assessment, null, ReviewStatus.NEW, "");
        assertTrue(new Exporter().csv(List.of(candidate)).contains("\"'=HYPERLINK"));
    }

    @Test void privacyModeOmitsNotesCompletely() {
        Assessment assessment = new Assessment("example.test|POST|/account", "Sensitive", "Cookie", true,
                "No token", "", "Origin absent", "SameSite unknown", "Browser-forgeable",
                Priority.REVIEW_1, "High", List.of());
        Candidate candidate = new Candidate("key", assessment, null, ReviewStatus.NEW, "private reviewer note token=secret-value");
        String json = new Exporter().json(List.of(candidate), false);
        assertFalse(json.contains("private reviewer note"));
        assertFalse(json.contains("note"));
    }

    @Test void redactsJsonAssignmentsAndInlineAuthorizationSchemes() {
        String redacted = Redaction.redact("{\"client_secret\":\"raw-value\"} Bearer abcdefghijklmnop");
        assertFalse(redacted.contains("raw-value"));
        assertFalse(redacted.contains("abcdefghijklmnop"));
        assertTrue(redacted.contains("REDACTED"));
    }
}
