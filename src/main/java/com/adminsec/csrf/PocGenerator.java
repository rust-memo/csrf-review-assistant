package com.adminsec.csrf;

import burp.api.montoya.http.message.ContentType;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.requests.HttpRequest;

import java.net.URI;
import java.util.Locale;
import java.util.Optional;

public final class PocGenerator {
    public Optional<String> generate(HttpRequest request, String tokenName) {
        String method = request.method().toUpperCase(Locale.ROOT);
        if (request.hasHeader("Upgrade", "websocket") || request.hasHeader("Sec-WebSocket-Key")) return Optional.empty();
        // HTML forms only preserve GET and POST semantics. Converting PUT/PATCH/DELETE
        // would test a different request and could produce a misleading result.
        if (!method.equals("GET") && !(method.equals("POST") && request.contentType() == ContentType.URL_ENCODED))
            return Optional.empty();
        String requestUrl = request.url();
        try {
            String scheme = URI.create(requestUrl).getScheme();
            if (!"http".equalsIgnoreCase(scheme) && !"https".equalsIgnoreCase(scheme)) return Optional.empty();
        } catch (IllegalArgumentException | NullPointerException invalid) { return Optional.empty(); }
        String action = method.equals("GET") ? requestUrl.split("\\?", 2)[0] : requestUrl;
        HttpParameterType parameterType = method.equals("GET") ? HttpParameterType.URL : HttpParameterType.BODY;
        StringBuilder html = new StringBuilder("<!doctype html>\n<meta charset=\"utf-8\">\n<title>CSRF manual test</title>\n")
                .append("<!-- Generated locally. Review the target and fields before submitting. -->\n")
                .append("<form action=\"").append(escape(action)).append("\" method=\"")
                .append(method).append("\">\n");
        request.parameters().stream()
                .filter(p -> p.type() == parameterType)
                .filter(p -> tokenName == null || !TrafficContext.normalize(p.name()).equals(TrafficContext.normalize(tokenName)))
                .forEach(p -> html.append("  <input type=\"hidden\" name=\"").append(escape(p.name())).append("\" value=\"")
                        .append(escape(p.value())).append("\">\n"));
        html.append("  <button type=\"submit\">Submit manual CSRF test</button>\n</form>\n");
        return Optional.of(html.toString());
    }
    private static String escape(String value) {
        return value == null ? "" : value.replace("&", "&amp;").replace("\"", "&quot;").replace("<", "&lt;").replace(">", "&gt;");
    }
}
