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
        assertTrue(result.exploitability().contains("non-simple method"));
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

    @Test void browserForgeableGraphqlMutationIsHighPriority() {
        Assessment result = analyze("POST", "/graphql", "text/plain", Map.of("Cookie", "session=abc"),
                List.of(), "mutation DeleteUser { deleteUser }").orElseThrow();
        assertEquals(Priority.REVIEW_1, result.priority());
    }

    @Test void nonSimpleMethodsAreNeverReportedAsDirectlyBrowserForgeable() {
        Assessment result = analyze("PATCH", "/account/email", "application/x-www-form-urlencoded",
                Map.of("Cookie", "session=abc"), fields("email", "x", "BODY"), "email=x").orElseThrow();
        assertEquals(Priority.REVIEW_2, result.priority());
        assertTrue(result.exploitability().contains("non-simple method"));
    }

    @Test void irrelevantCustomHeaderDoesNotHideForgeableForm() {
        Assessment result = analyze("POST", "/account/email", "application/x-www-form-urlencoded",
                Map.of("Cookie", "session=abc", "X-Correlation-ID", "trace-123"),
                fields("email", "x", "BODY"), "email=x").orElseThrow();
        assertEquals(Priority.REVIEW_1, result.priority());
        assertTrue(result.reasons().stream().anyMatch(reason -> reason.contains("X-Correlation-ID")));
    }

    @Test void unsafeStaticLookingEndpointIsStillAnalyzed() {
        assertEquals(Priority.REVIEW_1, analyze("POST", "/account/avatar.png", "application/x-www-form-urlencoded",
                Map.of("Cookie", "session=abc"), fields("profile", "x", "BODY"), "profile=x").orElseThrow().priority());
    }

    @Test void methodOverrideMakesOtherwiseGenericFormSensitive() {
        Assessment result = analyze("POST", "/action", "application/x-www-form-urlencoded",
                Map.of("Cookie", "session=abc"), fields("_method", "DELETE", "BODY"), "_method=DELETE").orElseThrow();
        assertEquals(Priority.REVIEW_1, result.priority());
        assertTrue(result.reasons().stream().anyMatch(reason -> reason.contains("Method override")));
    }

    @Test void detectsLoginCsrfWithoutAnAuthenticatedCookie() {
        Assessment result = analyze("POST", "/login", "application/x-www-form-urlencoded", Map.of(),
                fields("username", "attacker", "BODY"), "username=attacker").orElseThrow();
        assertEquals(Priority.REVIEW_1, result.priority());
        assertEquals("Login workflow", result.actionType());
    }

    @Test void nonSimpleLoginWorkflowRemainsVisibleAsP2() {
        Assessment result = analyze("POST", "/login", "application/json", Map.of(),
                fields("username", "attacker", "JSON"), "{\"username\":\"attacker\"}").orElseThrow();
        assertEquals(Priority.REVIEW_2, result.priority());
    }

    @Test void oauthStateIsOnlyProtectionInAnOauthWorkflow() {
        List<AnalysisInput.InputField> fields = List.of(
                new AnalysisInput.InputField("code", "authorization-code", "URL"),
                new AnalysisInput.InputField("state", "a1b2c3d4e5f6g7h8", "URL"));
        Assessment result = analyze("GET", "/oauth/callback", "", Map.of(), fields, "").orElseThrow();
        assertEquals(Priority.PROTECTED, result.priority());
        assertEquals("state", result.tokenName());

        Assessment ordinary = analyze("POST", "/account/email", "application/x-www-form-urlencoded",
                Map.of("Cookie", "session=abc"), fields("state", "a1b2c3d4e5f6g7h8", "BODY"), "state=x").orElseThrow();
        assertEquals(Priority.REVIEW_1, ordinary.priority());
        assertTrue(ordinary.tokenEvidence().contains("No CSRF token"));
    }

    @Test void recordsFetchMetadataOriginRelationshipAndCorsEvidence() {
        AnalysisInput input = new AnalysisInput("POST", "https://example.test/account/email", "example.test",
                "/account/email", "application/x-www-form-urlencoded",
                Map.of("Cookie", "session=abc", "Origin", "https://attacker.test", "Sec-Fetch-Site", "cross-site"),
                fields("email", "x", "BODY"), "email=x", "", List.of(),
                Map.of("Access-Control-Allow-Origin", "https://attacker.test", "Access-Control-Allow-Credentials", "true"), 200);
        Assessment result = analyzer.analyze(input).orElseThrow();
        assertTrue(result.originEvidence().contains("cross-origin"));
        assertTrue(result.fetchMetadataEvidence().contains("Site=cross-site"));
        assertTrue(result.corsEvidence().contains("credentialed cross-origin"));
    }

    @Test void detectsPersistedGraphqlGetForManualReview() {
        Assessment result = analyze("GET", "/graphql", "", Map.of("Cookie", "session=abc"),
                fields("extensions", "{\"persistedQuery\":{\"sha256Hash\":\"abc\"}}", "URL"), "").orElseThrow();
        assertEquals(Priority.REVIEW_2, result.priority());
        assertTrue(result.actionType().contains("persisted"));
    }

    @Test void supportsUnicodeSensitiveWordsWithoutCreatingAnEmptyMatcher() {
        settings.update(true, CsrfSettings.Sensitivity.CONSERVATIVE, 10_000, 1_048_576,
                "", "", "حذف", "", "");
        Assessment result = analyze("POST", "/api/حذف", "application/x-www-form-urlencoded",
                Map.of("Cookie", "session=abc"), List.of(), "confirm=yes").orElseThrow();
        assertEquals(Priority.REVIEW_1, result.priority());
        assertTrue(settings.customSensitiveWords().contains("حذف"));
    }

    @Test void learnsHiddenTokenWhenValueAttributeComesBeforeName() {
        context.observe("example.test", "<input value='abc123456789xyz987' type='hidden' name='transactionNonce'>", List.of());
        Assessment result = analyze("POST", "/payment/transfer", "application/x-www-form-urlencoded",
                Map.of("Cookie", "session=abc"), fields("transactionNonce", "abc123456789xyz987", "BODY"),
                "transactionNonce=abc123456789xyz987").orElseThrow();
        assertEquals(Priority.PROTECTED, result.priority());
    }

    @Test void cookiePathDoesNotLeakStrictEvidenceToUnrelatedEndpoint() {
        context.observe("https://example.test/admin/login", "example.test", "/admin/login", "",
                List.of("session=abc; Path=/admin; SameSite=Strict"));
        Assessment result = analyze("POST", "/account/delete", "application/x-www-form-urlencoded",
                Map.of("Cookie", "session=abc"), List.of(), "confirm=yes").orElseThrow();
        assertEquals("SameSite unknown", result.cookieDefense());
        assertEquals(Priority.REVIEW_1, result.priority());
    }

    @Test void detectsCookieAuthenticatedWebSocketHandshakeAsCswsHCandidate() {
        Assessment result = analyze("GET", "/socket", "",
                Map.of("Cookie", "session=abc", "Upgrade", "websocket", "Sec-WebSocket-Key", "base64-key",
                        "Origin", "https://example.test"), List.of(), "").orElseThrow();
        assertEquals("WebSocket CSWSH handshake", result.actionType());
        assertEquals(Priority.REVIEW_1, result.priority());
        assertTrue(result.corsEvidence().contains("does not govern WebSocket"));
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
