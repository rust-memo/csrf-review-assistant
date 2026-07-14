package com.adminsec.csrf;

import java.net.URI;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class TrafficContext {
    private static final Pattern TAG = Pattern.compile("(?is)<(?:input|meta)\\b[^>]*>");
    private static final Pattern ATTRIBUTE = Pattern.compile(
            "(?is)([A-Za-z_:][A-Za-z0-9_:.-]*)\\s*=\\s*(?:\"([^\"]*)\"|'([^']*)'|([^\\s>]+))");
    private final Map<String, Set<String>> learnedTokenNames = new ConcurrentHashMap<>();
    private final Map<String, CookieState> cookies = new ConcurrentHashMap<>();

    public void observe(String host, String responseBody, List<String> setCookies) {
        observe("https://" + (host == null ? "" : host) + "/", host, "/", responseBody, setCookies);
    }

    public void observe(String url, String host, String requestPath, String responseBody, List<String> setCookies) {
        String normalizedHost = lower(host);
        learnTokens(normalizedHost, responseBody);
        if (normalizedHost.isBlank()) return;

        for (String header : setCookies == null ? List.<String>of() : setCookies) {
            CookieState state = parseCookie(normalizedHost, requestPath, header);
            if (state == null) continue;
            String key = state.key();
            if (state.deleted()) cookies.remove(key);
            else if (cookies.containsKey(key) || cookies.size() < 20_000) cookies.put(key, state);
        }
    }

    private void learnTokens(String host, String responseBody) {
        if (responseBody == null || responseBody.length() > 2_000_000) return;
        Set<String> hostTokens = learnedTokenNames.computeIfAbsent(host, ignored -> ConcurrentHashMap.newKeySet());
        Matcher tags = TAG.matcher(responseBody);
        while (tags.find()) {
            Map<String, String> attributes = new HashMap<>();
            Matcher matcher = ATTRIBUTE.matcher(tags.group());
            while (matcher.find()) {
                String value = matcher.group(2) != null ? matcher.group(2) : matcher.group(3) != null ? matcher.group(3) : matcher.group(4);
                attributes.putIfAbsent(matcher.group(1).toLowerCase(Locale.ROOT), htmlDecode(value));
            }
            String name = normalize(attributes.getOrDefault("name", attributes.get("id")));
            String value = attributes.getOrDefault("value", attributes.getOrDefault("content", ""));
            if (hostTokens.size() < 256 && (looksTokenName(name) || (name.contains("nonce") && entropyLike(value)))) hostTokens.add(name);
        }
    }

    private static CookieState parseCookie(String responseHost, String requestPath, String header) {
        if (header == null || header.isBlank()) return null;
        String[] parts = header.split(";");
        int equals = parts[0].indexOf('=');
        if (equals <= 0) return null;
        String name = normalize(parts[0].substring(0, equals));
        if (name.isBlank()) return null;

        String domain = responseHost;
        boolean hostOnly = true, secure = false, deleted = false;
        String path = defaultCookiePath(requestPath), sameSite = "Unspecified";
        for (int index = 1; index < parts.length; index++) {
            String part = parts[index].trim();
            int attributeEquals = part.indexOf('=');
            String attribute = (attributeEquals < 0 ? part : part.substring(0, attributeEquals)).trim().toLowerCase(Locale.ROOT);
            String attributeValue = attributeEquals < 0 ? "" : unquote(part.substring(attributeEquals + 1).trim());
            if (attribute.equals("samesite")) sameSite = attributeValue;
            else if (attribute.equals("domain")) {
                domain = lower(attributeValue).replaceFirst("^\\.+", "");
                hostOnly = false;
            } else if (attribute.equals("path")) path = normalizeCookiePath(attributeValue);
            else if (attribute.equals("secure")) secure = true;
            else if (attribute.equals("max-age")) {
                try { deleted = Long.parseLong(attributeValue) <= 0; }
                catch (NumberFormatException ignored) { }
            }
        }
        if (!hostOnly && !domainMatches(responseHost, domain, false)) return null;
        return new CookieState(name, domain, hostOnly, path, sameSite, secure, deleted);
    }

    public boolean isLearnedTokenName(String host, String name) {
        return learnedTokenNames.getOrDefault(lower(host), Set.of()).contains(normalize(name));
    }

    public String sameSite(String host, String cookieName) {
        return sameSite("https://" + (host == null ? "" : host) + "/", host, "/", cookieName);
    }

    public String sameSite(String url, String host, String requestPath, String cookieName) {
        String requestHost = lower(host), normalizedName = normalize(cookieName);
        boolean secureRequest = isSecure(url);
        List<String> matches = cookies.values().stream()
                .filter(cookie -> cookie.name.equals(normalizedName))
                .filter(cookie -> domainMatches(requestHost, cookie.domain, cookie.hostOnly))
                .filter(cookie -> pathMatches(requestPath, cookie.path))
                .filter(cookie -> !cookie.secure || secureRequest)
                .map(cookie -> cookie.sameSite.toLowerCase(Locale.ROOT)).toList();
        if (matches.isEmpty()) return "Unknown";
        if (matches.stream().anyMatch(value -> value.equals("none") || value.equals("unspecified") || value.equals("unknown")))
            return matches.stream().anyMatch(value -> value.equals("none")) ? "None" : "Unspecified";
        if (matches.stream().anyMatch(value -> value.equals("lax"))) return "Lax";
        if (matches.stream().allMatch(value -> value.equals("strict"))) return "Strict";
        return "Unknown";
    }

    public Set<String> learnedTokenNames(String host) {
        return Set.copyOf(learnedTokenNames.getOrDefault(lower(host), Set.of()));
    }

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

    private static boolean domainMatches(String host, String domain, boolean hostOnly) {
        return hostOnly ? host.equals(domain) : host.equals(domain) || host.endsWith("." + domain);
    }
    private static boolean pathMatches(String requestPath, String cookiePath) {
        String request = normalizeCookiePath(requestPath);
        return request.equals(cookiePath) || request.startsWith(cookiePath.endsWith("/") ? cookiePath : cookiePath + "/");
    }
    private static String defaultCookiePath(String requestPath) {
        String path = normalizeCookiePath(requestPath);
        int slash = path.lastIndexOf('/');
        return slash <= 0 ? "/" : path.substring(0, slash);
    }
    private static String normalizeCookiePath(String path) {
        if (path == null || path.isBlank() || path.charAt(0) != '/') return "/";
        return path.split("[?#]", 2)[0];
    }
    private static boolean isSecure(String url) {
        try {
            String scheme = URI.create(url == null ? "" : url).getScheme();
            return "https".equalsIgnoreCase(scheme) || "wss".equalsIgnoreCase(scheme);
        }
        catch (IllegalArgumentException ignored) { return false; }
    }
    private static String htmlDecode(String value) {
        if (value == null) return "";
        return value.replace("&quot;", "\"").replace("&#39;", "'").replace("&apos;", "'")
                .replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&");
    }
    private static String unquote(String value) {
        if (value != null && value.length() >= 2
                && ((value.startsWith("\"") && value.endsWith("\"")) || (value.startsWith("'") && value.endsWith("'"))))
            return value.substring(1, value.length() - 1);
        return value == null ? "" : value;
    }
    private static String lower(String value) { return value == null ? "" : value.toLowerCase(Locale.ROOT); }

    private record CookieState(String name, String domain, boolean hostOnly, String path,
                               String sameSite, boolean secure, boolean deleted) {
        String key() { return name + '|' + domain + '|' + hostOnly + '|' + path; }
    }
}
