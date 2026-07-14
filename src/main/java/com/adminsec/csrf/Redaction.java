package com.adminsec.csrf;

import java.util.regex.Pattern;

public final class Redaction {
    private static final Pattern HEADER = Pattern.compile("(?im)^(authorization|proxy-authorization|cookie|set-cookie|x-api-key|api-key)\\s*:\\s*.*$");
    private static final Pattern JSON_ASSIGNMENT = Pattern.compile("(?i)\"(password|passwd|secret|client[_-]?secret|api[_-]?key|session(?:id)?|(?:access|refresh|csrf|xsrf|auth)?[_-]?token)\"\\s*:\\s*\"[^\"]*\"");
    private static final Pattern ASSIGNMENT = Pattern.compile("(?i)\\b(password|passwd|secret|client[_-]?secret|api[_-]?key|session(?:id)?|access[_-]?token|refresh[_-]?token|auth[_-]?token|csrf(?:[_-]?token)?|xsrf(?:[_-]?token)?|token)\\s*[=:]\\s*([^\\s,;&]+)");
    private static final Pattern AUTH_SCHEME = Pattern.compile("(?i)\\b(Bearer|Basic|Digest)\\s+[A-Za-z0-9._~+/=-]{8,}");
    private static final Pattern JWT = Pattern.compile("\\beyJ[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}\\b");
    private Redaction() { }
    public static String redact(String value) {
        if (value == null || value.isBlank()) return value == null ? "" : value;
        String safe = HEADER.matcher(value).replaceAll("$1: [REDACTED]");
        safe = JSON_ASSIGNMENT.matcher(safe).replaceAll("\"$1\":\"[REDACTED]\"");
        safe = ASSIGNMENT.matcher(safe).replaceAll("$1=[REDACTED]");
        safe = AUTH_SCHEME.matcher(safe).replaceAll("$1 [REDACTED]");
        return JWT.matcher(safe).replaceAll("[REDACTED JWT]");
    }
}
