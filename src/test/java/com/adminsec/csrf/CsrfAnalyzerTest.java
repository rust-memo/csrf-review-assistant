package com.adminsec.csrf;

import com.adminsec.csrf.model.*;
import org.junit.jupiter.api.Test;

import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

class CsrfAnalyzerTest {
    private final CsrfSettings settings = new CsrfSettings();
    private final TrafficContext context = new TrafficContext();
    private final CsrfAnalyzer analyzer = new CsrfAnalyzer(settings, context);

    @Test void flagsSensitiveFormWithSessionCookieAndNoTokenAsP1() {
        Assessment result = analyze("POST", "/account/change-email", "application/x-www-form-urlencoded",
                Map.of("Cookie", "session=abc123"), fields("email", "new@example.test", "BODY"), "email=new%40example.test").orElseThrow();
        assertEquals(Priority.REVIEW_1, result.priority());
        assertEquals("Browser-forgeable", result.exploitability());
        assertTrue(result.ambientAuthentication());
    }

    @Test void recordsTokenButNeverClaimsServerValidation() {
        Assessment result = analyze("POST", "/account/password", "application/x-www-form-urlencoded",
                Map.of("Cookie", "session=abc"), fields("csrf_token", "a1b2c3d4e5f6g7h8", "BODY"), "csrf_token=a1b2c3d4e5f6g7h8").orElseThrow();
        assertEquals(Priority.PROTECTED, result.priority());
        assertTrue(result.tokenEvidence().contains("validation unverified"));
    }

    @Test void csrfNamedCookieAloneIsNotAcceptedAsProtection() {
        Assessment result = analyze("POST", "/account/email", "application/x-www-form-urlencoded",
                Map.of("Cookie", "session=abc; XSRF-TOKEN=a1b2c3d4e5f6g7h8"),
                List.of(new AnalysisInput.InputField("XSRF-TOKEN", "a1b2c3d4e5f6g7h8", "COOKIE")), "email=x").orElseThrow();
        assertEquals(Priority.REVIEW_1, result.priority());
        assertTrue(result.tokenEvidence().contains("No CSRF token"));
    }

    @Test void suppressesBearerOnlyApiInConservativeMode() {
        assertTrue(analyze("PATCH", "/api/account", "application/json", Map.of("Authorization", "Bearer secret"),
                fields("email", "x", "JSON"), "{\"email\":\"x\"}").isEmpty());
    }

    @Test void jsonRequestIsCandidateButBrowserBarrierReducesPriority() {
        Assessment result = analyze("PATCH", "/api/account/email", "application/json", Map.of("Cookie", "session=abc"),
                fields("email", "x", "JSON"), "{\"email\":\"x\"}").orElseThrow();
        assertEquals(Priority.REVIEW_2, result.priority());
        assertEquals("Reduced by Content-Type", result.exploitability());
    }

    @Test void sameSiteStrictIsEvidenceNotAutomaticProof() {
        context.observe("example.test", "", List.of("session=abc; Secure; SameSite=Strict"));
        Assessment result = analyze("POST", "/account/delete", "application/x-www-form-urlencoded", Map.of("Cookie", "session=abc"), List.of(), "confirm=yes").orElseThrow();
        assertEquals("SameSite=Strict", result.cookieDefense());
        assertEquals(Priority.REVIEW_2, result.priority());
    }

    @Test void originHeaderDoesNotTurnCandidateIntoProtected() {
        Assessment result = analyze("POST", "/account/delete", "application/x-www-form-urlencoded",
                Map.of("Cookie", "session=abc", "Origin", "https://example.test"), List.of(), "confirm=yes").orElseThrow();
        assertEquals(Priority.REVIEW_1, result.priority());
        assertTrue(result.originEvidence().contains("validation unverified"));
    }

    @Test void sensitiveGetIsIncludedButOrdinaryGetIsIgnored() {
        assertEquals(Priority.REVIEW_1, analyze("GET", "/account/delete", "", Map.of("Cookie", "session=abc"), List.of(), "").orElseThrow().priority());
        assertTrue(analyze("GET", "/products/search", "", Map.of("Cookie", "session=abc"), fields("q", "hat", "URL"), "").isEmpty());
    }

    @Test void learnsCustomNonceFromHtmlAndRecognizesItLater() {
        context.observe("example.test", "<input type='hidden' name='transactionNonce' value='abc123456789xyz987'>", List.of());
        Assessment result = analyze("POST", "/payment/transfer", "application/x-www-form-urlencoded", Map.of("Cookie", "session=abc"),
                fields("transactionNonce", "abc123456789xyz987", "BODY"), "transactionNonce=abc123456789xyz987").orElseThrow();
        assertEquals(Priority.PROTECTED, result.priority());
        assertEquals("transactionnonce", result.tokenName());
    }

    @Test void graphqlMutationIsDetected() {
        Assessment result = analyze("POST", "/graphql", "application/json", Map.of("Cookie", "session=abc"),
                fields("email", "x", "JSON"), "mutation ChangeEmail { changeEmail(email: \"x\") }").orElseThrow();
        assertEquals("GraphQL mutation: ChangeEmail", result.actionType());
    }

    private Optional<Assessment> analyze(String method, String path, String type, Map<String, String> headers,
                                         List<AnalysisInput.InputField> fields, String body) {
        return analyzer.analyze(new AnalysisInput(method, "https://example.test" + path, "example.test", path, type,
                headers, fields, body, "", List.of()));
    }
    private static List<AnalysisInput.InputField> fields(String name, String value, String location) {
        return List.of(new AnalysisInput.InputField(name, value, location));
    }
}
