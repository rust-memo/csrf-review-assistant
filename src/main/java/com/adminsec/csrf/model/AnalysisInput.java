package com.adminsec.csrf.model;

import java.util.List;
import java.util.Map;

public record AnalysisInput(
        String method,
        String url,
        String host,
        String path,
        String contentType,
        Map<String, String> headers,
        List<InputField> fields,
        String body,
        String responseBody,
        List<String> setCookieHeaders) {

    public record InputField(String name, String value, String location) { }
}
