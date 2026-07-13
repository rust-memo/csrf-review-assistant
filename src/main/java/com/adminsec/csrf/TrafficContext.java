package com.adminsec.csrf;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class TrafficContext {
    private static final Pattern FIELD = Pattern.compile("(?is)<(?:input|meta)\\b[^>]*(?:name|id)\\s*=\\s*['\"]([^'\"]+)['\"][^>]*(?:value|content)\\s*=\\s*['\"]([^'\"]+)['\"]");
    private final Map<String, Set<String>> learnedTokenNames = new ConcurrentHashMap<>();
    private final Map<String, Map<String, String>> cookieAttributes = new ConcurrentHashMap<>();

    public void observe(String host, String responseBody, List<String> setCookies) {
        String normalizedHost = host == null ? "" : host.toLowerCase(Locale.ROOT);
        Set<String> hostTokens = learnedTokenNames.computeIfAbsent(normalizedHost, ignored -> ConcurrentHashMap.newKeySet());
        if (responseBody != null && responseBody.length() <= 2_000_000) {
            Matcher matcher = FIELD.matcher(responseBody);
            while (matcher.find()) {
                String name = normalize(matcher.group(1));
                String value = matcher.group(2);
                if (looksTokenName(name) || (name.contains("nonce") && entropyLike(value))) hostTokens.add(name);
            }
        }
        if (host == null) return;
        Map<String, String> hostCookies = cookieAttributes.computeIfAbsent(host.toLowerCase(Locale.ROOT), ignored -> new ConcurrentHashMap<>());
        for (String header : setCookies == null ? List.<String>of() : setCookies) {
            String[] parts = header.split(";");
            int equals = parts[0].indexOf('=');
            if (equals <= 0) continue;
            String name = normalize(parts[0].substring(0, equals));
            String sameSite = "Unspecified";
            for (String part : parts) {
                String lower = part.trim().toLowerCase(Locale.ROOT);
                if (lower.startsWith("samesite=")) sameSite = lower.substring(9);
            }
            hostCookies.put(name, sameSite);
        }
    }

    public boolean isLearnedTokenName(String host, String name) {
        return learnedTokenNames.getOrDefault(host == null ? "" : host.toLowerCase(Locale.ROOT), Set.of()).contains(normalize(name));
    }
    public String sameSite(String host, String cookieName) {
        Map<String, String> values = cookieAttributes.getOrDefault(host == null ? "" : host.toLowerCase(Locale.ROOT), Map.of());
        return values.getOrDefault(normalize(cookieName), "Unknown");
    }
    public Set<String> learnedTokenNames(String host) { return Set.copyOf(learnedTokenNames.getOrDefault(host == null ? "" : host.toLowerCase(Locale.ROOT), Set.of())); }

    static boolean entropyLike(String value) {
        if (value == null || value.length() < 16 || value.length() > 512) return false;
        boolean letter = false, digit = false;
        for (char c : value.toCharArray()) { letter |= Character.isLetter(c); digit |= Character.isDigit(c); }
        return letter && digit;
    }
    static boolean looksTokenName(String name) {
        String n = normalize(name);
        return n.contains("csrf") || n.contains("xsrf") || n.contains("requesttoken") || n.contains("authenticitytoken") || n.equals("_token");
    }
    static String normalize(String value) {
        return value == null ? "" : value.trim().toLowerCase(Locale.ROOT).replace('-', '_').replace('.', '_').replaceAll("[^a-z0-9_]", "");
    }
}
