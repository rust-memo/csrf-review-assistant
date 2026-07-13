package com.adminsec.csrf;

import java.util.regex.Pattern;

public final class Redaction {
    private static final Pattern HEADER = Pattern.compile("(?im)^(authorization|proxy-authorization|cookie|set-cookie)\\s*:\\s*.*$");
    private static final Pattern ASSIGNMENT = Pattern.compile("(?i)\\b(password|passwd|secret|api[_-]?key|access[_-]?token|refresh[_-]?token|csrf(?:[_-]?token)?|xsrf(?:[_-]?token)?)\\s*[=:]\\s*([^\\s,;&]+)");
    private static final Pattern JWT = Pattern.compile("\\beyJ[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}\\b");
    private Redaction() { }
    public static String redact(String value) {
        if (value == null || value.isBlank()) return value == null ? "" : value;
        String safe = HEADER.matcher(value).replaceAll("$1: [REDACTED]");
        safe = ASSIGNMENT.matcher(safe).replaceAll("$1=[REDACTED]");
        return JWT.matcher(safe).replaceAll("[REDACTED JWT]");
    }
}
