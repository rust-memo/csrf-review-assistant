package com.adminsec.csrf;

import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.adminsec.csrf.model.AnalysisInput;

import java.util.*;

public final class MessageAdapter {
    private MessageAdapter() { }
    public static AnalysisInput input(HttpRequestResponse message, int maxBodyBytes) {
        HttpRequest request = message.request(); HttpResponse response = message.hasResponse() ? message.response() : null;
        Map<String, String> headers = headers(request.headers());
        List<AnalysisInput.InputField> fields = request.parameters().stream()
                .map(p -> new AnalysisInput.InputField(p.name(), p.value(), p.type().name())).toList();
        String body = request.body().length() <= maxBodyBytes ? request.bodyToString() : "";
        String responseBody = response != null && response.body().length() <= maxBodyBytes ? response.bodyToString() : "";
        List<String> setCookies = response == null ? List.of() : response.headers().stream()
                .filter(h -> h.name().equalsIgnoreCase("Set-Cookie")).map(HttpHeader::value).toList();
        return new AnalysisInput(request.method(), request.url(), request.httpService().host(), request.pathWithoutQuery(),
                request.headerValue("Content-Type"), headers, fields, body, responseBody, setCookies);
    }
    private static Map<String, String> headers(List<HttpHeader> input) {
        Map<String, String> result = new LinkedHashMap<>();
        for (HttpHeader header : input) result.merge(header.name(), header.value(), (a, b) -> a + ", " + b);
        return result;
    }
}
