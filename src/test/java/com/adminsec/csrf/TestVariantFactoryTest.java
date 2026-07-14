package com.adminsec.csrf;

import burp.api.montoya.http.message.ContentType;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.adminsec.csrf.model.*;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class TestVariantFactoryTest {
    @Test void buildsVariantsWithoutSendingAndPreservesActionFields() {
        HttpRequest request = mock(HttpRequest.class), removed = mock(HttpRequest.class), empty = mock(HttpRequest.class), random = mock(HttpRequest.class);
        ParsedHttpParameter token = mock(ParsedHttpParameter.class); when(token.name()).thenReturn("csrf_token"); when(token.value()).thenReturn("abcdefghijklmnop"); when(token.type()).thenReturn(HttpParameterType.BODY);
        when(request.parameters()).thenReturn(List.of(token)); when(request.withRemovedParameters(anyList())).thenReturn(removed);
        when(request.withUpdatedParameters(anyList())).thenReturn(empty, random); when(request.hasHeader(anyString())).thenReturn(false);
        when(request.withAddedHeader(anyString(), anyString())).thenReturn(request); when(request.withRemovedHeader(anyString())).thenReturn(request);
        Assessment assessment = new Assessment("key", "Sensitive", "session", true, "observed", "csrf_token", "origin", "unknown", "Browser-forgeable", Priority.PROTECTED, "Medium", List.of());
        HttpParameter replacement = mock(HttpParameter.class);
        try (var factory = mockStatic(HttpParameter.class)) {
            factory.when(() -> HttpParameter.parameter(eq("csrf_token"), anyString(), eq(HttpParameterType.BODY))).thenReturn(replacement);
            List<TestVariantFactory.Variant> variants = new TestVariantFactory().create(request, assessment);
            assertEquals(6, variants.size());
            assertTrue(variants.stream().anyMatch(v -> v.label().contains("removed") && v.request() == removed));
            assertTrue(variants.stream().anyMatch(v -> v.label().contains("empty") && v.request() == empty));
            assertTrue(variants.stream().anyMatch(v -> v.label().contains("random") && v.request() == random));
            verify(request, never()).toByteArray();
        }
    }

    @Test void pocEscapesAttackerControlledFieldValuesAndOmitsToken() {
        HttpRequest request = mock(HttpRequest.class); ParsedHttpParameter name = mock(ParsedHttpParameter.class), token = mock(ParsedHttpParameter.class);
        when(request.method()).thenReturn("POST"); when(request.contentType()).thenReturn(ContentType.URL_ENCODED); when(request.url()).thenReturn("https://example.test/profile");
        when(name.name()).thenReturn("display_name"); when(name.value()).thenReturn("<script>"); when(name.type()).thenReturn(HttpParameterType.BODY);
        when(token.name()).thenReturn("csrf"); when(token.value()).thenReturn("abcdefghijklmnop"); when(token.type()).thenReturn(HttpParameterType.BODY);
        when(request.parameters()).thenReturn(List.of(name, token));
        String poc = new PocGenerator().generate(request, "csrf").orElseThrow();
        assertFalse(poc.contains("name=\"csrf\""));
        assertFalse(poc.contains("<script>"));
        assertTrue(poc.contains("&lt;script&gt;"));
    }

    @Test void pocRejectsMethodsHtmlFormsCannotRepresent() {
        HttpRequest request = mock(HttpRequest.class);
        when(request.method()).thenReturn("PATCH"); when(request.contentType()).thenReturn(ContentType.URL_ENCODED);
        assertTrue(new PocGenerator().generate(request, "csrf").isEmpty());
    }

    @Test void pocRejectsWebSocketHandshake() {
        HttpRequest request = mock(HttpRequest.class);
        when(request.method()).thenReturn("GET"); when(request.hasHeader("Upgrade", "websocket")).thenReturn(true);
        assertTrue(new PocGenerator().generate(request, "csrf").isEmpty());
    }

    @Test void pocRejectsNonHttpActionUrl() {
        HttpRequest request = mock(HttpRequest.class);
        when(request.method()).thenReturn("GET"); when(request.url()).thenReturn("javascript:alert(1)");
        assertTrue(new PocGenerator().generate(request, "csrf").isEmpty());
    }

    @Test void pocKeepsPostQueryParametersInActionAndBodyParametersInBody() {
        HttpRequest request = mock(HttpRequest.class);
        ParsedHttpParameter query = mock(ParsedHttpParameter.class), body = mock(ParsedHttpParameter.class);
        when(request.method()).thenReturn("POST"); when(request.contentType()).thenReturn(ContentType.URL_ENCODED);
        when(request.url()).thenReturn("https://example.test/profile?tenant=blue");
        when(query.name()).thenReturn("tenant"); when(query.value()).thenReturn("blue"); when(query.type()).thenReturn(HttpParameterType.URL);
        when(body.name()).thenReturn("display_name"); when(body.value()).thenReturn("Alice"); when(body.type()).thenReturn(HttpParameterType.BODY);
        when(request.parameters()).thenReturn(List.of(query, body));
        String poc = new PocGenerator().generate(request, "csrf").orElseThrow();
        assertTrue(poc.contains("action=\"https://example.test/profile?tenant=blue\""));
        assertFalse(poc.contains("name=\"tenant\""));
        assertTrue(poc.contains("name=\"display_name\""));
    }

    @SuppressWarnings({"unchecked", "rawtypes"})
    @Test void tokenCookieIsNotRemovedWithRequestTokenParameter() {
        HttpRequest request = mock(HttpRequest.class), removed = mock(HttpRequest.class);
        ParsedHttpParameter body = mock(ParsedHttpParameter.class), cookie = mock(ParsedHttpParameter.class);
        when(body.name()).thenReturn("csrf"); when(body.type()).thenReturn(HttpParameterType.BODY);
        when(cookie.name()).thenReturn("csrf"); when(cookie.type()).thenReturn(HttpParameterType.COOKIE);
        when(request.parameters()).thenReturn(List.of(body, cookie)); when(request.withRemovedParameters(anyList())).thenReturn(removed);
        when(request.withUpdatedParameters(anyList())).thenReturn(request); when(request.hasHeader(anyString())).thenReturn(false);
        when(request.withAddedHeader(anyString(), anyString())).thenReturn(request); when(request.withRemovedHeader(anyString())).thenReturn(request);
        Assessment assessment = new Assessment("key", "Sensitive", "session", true, "observed", "csrf",
                "origin", "unknown", "Browser-forgeable", Priority.PROTECTED, "Medium", List.of());
        HttpParameter replacement = mock(HttpParameter.class);
        try (var factory = mockStatic(HttpParameter.class)) {
            factory.when(() -> HttpParameter.parameter(eq("csrf"), anyString(), eq(HttpParameterType.BODY))).thenReturn(replacement);
            new TestVariantFactory().create(request, assessment);
        }
        @SuppressWarnings("unchecked") var captor = org.mockito.ArgumentCaptor.forClass(List.class);
        verify(request).withRemovedParameters(captor.capture());
        assertEquals(List.of(body), captor.getValue());
    }

    @Test void normalizedTokenHeaderUsesItsActualWireName() {
        HttpRequest request = mock(HttpRequest.class), removed = mock(HttpRequest.class);
        HttpHeader header = mock(HttpHeader.class); when(header.name()).thenReturn("X-CSRF-Token");
        when(request.parameters()).thenReturn(List.of()); when(request.headers()).thenReturn(List.of(header));
        when(request.hasHeader(anyString())).thenReturn(false); when(request.withAddedHeader(anyString(), anyString())).thenReturn(request);
        when(request.withRemovedHeader(anyString())).thenReturn(request); when(request.withRemovedHeader("X-CSRF-Token")).thenReturn(removed);
        when(request.withUpdatedHeader(anyString(), anyString())).thenReturn(request);
        Assessment assessment = new Assessment("key", "Sensitive", "session", true, "observed", "x_csrf_token",
                "origin", "unknown", "Browser-forgeable", Priority.PROTECTED, "Medium", List.of());
        List<TestVariantFactory.Variant> variants = new TestVariantFactory().create(request, assessment);
        assertTrue(variants.stream().anyMatch(variant -> variant.label().contains("header removed") && variant.request() == removed));
    }
}
