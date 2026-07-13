package com.adminsec.csrf;

import burp.api.montoya.http.message.ContentType;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.requests.HttpRequest;

import java.util.Locale;
import java.util.Optional;

public final class PocGenerator {
    public Optional<String> generate(HttpRequest request, String tokenName) {
        String method = request.method().toUpperCase(Locale.ROOT);
        if (!method.equals("GET") && request.contentType() != ContentType.URL_ENCODED && request.contentType() != ContentType.MULTIPART) return Optional.empty();
        StringBuilder html = new StringBuilder("<!doctype html>\n<meta charset=\"utf-8\">\n<title>CSRF manual test</title>\n")
                .append("<!-- Generated locally. Review the target and fields before submitting. -->\n")
                .append("<form action=\"").append(escape(request.url().split("\\?", 2)[0])).append("\" method=\"")
                .append(method.equals("GET") ? "GET" : "POST").append("\"");
        if (request.contentType() == ContentType.MULTIPART) html.append(" enctype=\"multipart/form-data\"");
        html.append(">\n");
        request.parameters().stream()
                .filter(p -> p.type() == HttpParameterType.URL || p.type() == HttpParameterType.BODY)
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
