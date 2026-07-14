package com.adminsec.csrf;

import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.adminsec.csrf.model.Assessment;

import java.security.SecureRandom;
import java.util.*;

public final class TestVariantFactory {
    private static final SecureRandom RANDOM = new SecureRandom();
    public record Variant(String label, HttpRequest request) { }

    public List<Variant> create(HttpRequest original, Assessment assessment) {
        List<Variant> result = new ArrayList<>();
        result.add(new Variant("00 original control", original));
        String tokenName = assessment.tokenName();
        if (tokenName != null && !tokenName.isBlank()) {
            List<ParsedHttpParameter> matching = original.parameters().stream()
                    .filter(p -> p.type() != HttpParameterType.COOKIE)
                    .filter(p -> normalize(p.name()).equals(normalize(tokenName))).toList();
            if (!matching.isEmpty()) {
                result.add(new Variant("01 token removed", original.withRemovedParameters(matching)));
                List<HttpParameter> empty = matching.stream().map(p -> HttpParameter.parameter(p.name(), "", p.type())).toList();
                List<HttpParameter> random = matching.stream().map(p -> HttpParameter.parameter(p.name(), randomToken(), p.type())).toList();
                result.add(new Variant("02 token empty", original.withUpdatedParameters(empty)));
                result.add(new Variant("03 token random", original.withUpdatedParameters(random)));
            } else {
                Optional<String> headerName = Optional.ofNullable(original.headers()).orElse(List.of()).stream().map(header -> header.name())
                        .filter(name -> normalize(name).equals(normalize(tokenName))).findFirst();
                if (headerName.isPresent()) {
                    String actual = headerName.get();
                    result.add(new Variant("01 token header removed", original.withRemovedHeader(actual)));
                    result.add(new Variant("02 token header empty", original.withUpdatedHeader(actual, "")));
                    result.add(new Variant("03 token header random", original.withUpdatedHeader(actual, randomToken())));
                }
            }
        }
        HttpRequest crossSite = setHeader(setHeader(setHeader(original, "Origin", "https://csrf.invalid"),
                "Referer", "https://csrf.invalid/poc"), "Sec-Fetch-Site", "cross-site");
        result.add(new Variant("10 cross-site origin", crossSite));
        result.add(new Variant("11 origin and referer omitted", original.withRemovedHeader("Origin").withRemovedHeader("Referer")));
        String contentType = Optional.ofNullable(original.headerValue("Content-Type")).orElse("").toLowerCase(Locale.ROOT);
        if ("POST".equalsIgnoreCase(original.method()) && (contentType.contains("json") || contentType.contains("xml")))
            result.add(new Variant("12 simple Content-Type text/plain", original.withUpdatedHeader("Content-Type", "text/plain")));
        return List.copyOf(result);
    }
    private static HttpRequest setHeader(HttpRequest request, String name, String value) {
        return request.hasHeader(name) ? request.withUpdatedHeader(name, value) : request.withAddedHeader(name, value);
    }
    private static String randomToken() {
        byte[] value = new byte[24]; RANDOM.nextBytes(value); return HexFormat.of().formatHex(value);
    }
    private static String normalize(String value) { return TrafficContext.normalize(value); }
}
