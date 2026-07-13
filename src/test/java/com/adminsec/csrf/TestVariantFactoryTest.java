package com.adminsec.csrf;

import burp.api.montoya.http.message.ContentType;
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
}
