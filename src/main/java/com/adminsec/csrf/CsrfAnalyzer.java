package com.adminsec.csrf;

import com.adminsec.csrf.model.*;

import java.net.URI;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class CsrfAnalyzer {
    private static final Set<String> TOKEN_NAMES = Set.of(
            "csrf", "csrf_token", "csrftoken", "csrfmiddlewaretoken", "xsrf_token", "xsrftoken",
            "_csrf", "_token", "authenticity_token", "request_verification_token", "__requestverificationtoken",
            "anticsrf", "anti_csrf", "form_token", "formtoken");
    private static final Set<String> TOKEN_HEADERS = Set.of(
            "x_csrf_token", "x_csrf", "x_xsrf_token", "x_srf_token", "x_requested_with", "requestverificationtoken");
    private static final Set<String> AUTH_COOKIES = Set.of(
            "session", "sessionid", "session_id", "sid", "jsessionid", "phpsessid", "aspsessionid",
            "asp_net_sessionid", "connect_sid", "auth", "auth_token", "access_token", "remember_me", "wordpress_logged_in");
    private static final Set<String> SENSITIVE = Set.of(
            "password", "passwd", "email", "phone", "profile", "account", "user", "admin", "role", "permission",
            "delete", "remove", "disable", "enable", "update", "change", "edit", "create", "invite", "transfer",
            "payment", "pay", "withdraw", "refund", "address", "mfa", "2fa", "totp", "api_key", "credential",
            "subscription", "checkout", "order", "upload", "message", "logout", "settings", "preference",
            "security", "username", "display_name", "first_name", "last_name");
    private static final Set<String> STATIC_EXT = Set.of("js", "css", "map", "png", "jpg", "jpeg", "gif", "svg", "ico", "woff", "woff2", "ttf", "mp4", "mp3", "pdf");
    private static final List<String> NOISE_PATHS = List.of("/analytics", "/telemetry", "/metrics", "/health", "/heartbeat", "/beacon");
    private static final Pattern JSON_FIELD = Pattern.compile("(?i)[\"']([A-Za-z_$][A-Za-z0-9_.$-]*)[\"']\\s*:\\s*[\"']([^\"']*)[\"']");
    private final CsrfSettings settings;
    private final TrafficContext context;

    public CsrfAnalyzer(CsrfSettings settings, TrafficContext context) { this.settings = settings; this.context = context; }

    public Optional<Assessment> analyze(AnalysisInput input) {
        if (input == null || input.method() == null) return Optional.empty();
        String method = input.method().toUpperCase(Locale.ROOT);
        String host = lower(input.host());
        String path = input.path() == null ? "/" : input.path();
        String lowerPath = path.toLowerCase(Locale.ROOT);
        if (settings.ignoredHosts().stream().anyMatch(host::equals) || settings.ignoredPaths().stream().anyMatch(lowerPath::contains)) return Optional.empty();
        if (Set.of("HEAD", "OPTIONS", "TRACE").contains(method) || staticAsset(lowerPath) || NOISE_PATHS.stream().anyMatch(lowerPath::contains)) return Optional.empty();

        Matcher graphQl = Pattern.compile("(?is)\\bmutation(?:\\s+([A-Za-z_][A-Za-z0-9_]*))?").matcher(input.body() == null ? "" : input.body());
        boolean graphQlMutation = graphQl.find();
        String graphQlOperation = graphQlMutation && graphQl.group(1) != null ? graphQl.group(1) : "anonymous";
        boolean unsafe = Set.of("POST", "PUT", "PATCH", "DELETE").contains(method) || graphQlMutation;
        boolean sensitive = sensitive(input);
        if (!unsafe && !(method.equals("GET") && sensitive)) return Optional.empty();

        Auth auth = authentication(input);
        if (!auth.ambient && settings.sensitivity() == CsrfSettings.Sensitivity.CONSERVATIVE) return Optional.empty();
        if (!auth.ambient && settings.sensitivity() == CsrfSettings.Sensitivity.BALANCED && !sensitive) return Optional.empty();

        Token token = token(input);
        String cookieDefense = cookieDefense(input, auth.cookieNames);
        String exploitability = exploitability(method, input.contentType(), input.headers());
        String origin = originEvidence(input.headers());
        Priority priority;
        String confidence;
        List<String> reasons = new ArrayList<>();
        reasons.add(graphQlMutation ? "GraphQL mutation changes server state" : method + (sensitive ? " request targets a sensitive action" : " may change server state"));
        reasons.add(auth.detail);
        reasons.add(token.detail);
        reasons.add("Browser exploitability: " + exploitability);
        reasons.add("Cookie defense: " + cookieDefense);

        if (token.status.equals("Observed")) {
            priority = Priority.PROTECTED;
            confidence = "Medium";
        } else if (token.status.equals("Weak")) {
            priority = Priority.REVIEW_2;
            confidence = "Medium";
        } else if (!auth.ambient) {
            priority = Priority.REVIEW_3;
            confidence = "Low";
        } else if (sensitive && exploitability.equals("Browser-forgeable") && !cookieMitigates(method, cookieDefense)) {
            priority = Priority.REVIEW_1;
            confidence = token.status.equals("Missing") ? "High" : "Medium";
        } else {
            priority = Priority.REVIEW_2;
            confidence = token.status.equals("Missing") ? "Medium" : "Low";
        }

        context.observe(host, input.responseBody(), input.setCookieHeaders());
        return Optional.of(new Assessment(endpointKey(method, input.url(), path, graphQlMutation ? graphQlOperation : ""),
                graphQlMutation ? "GraphQL mutation: " + graphQlOperation : sensitive ? "Sensitive state change" : "State change",
                auth.detail, auth.ambient, token.detail, token.name, origin, cookieDefense, exploitability,
                priority, confidence, List.copyOf(reasons)));
    }

    private Auth authentication(AnalysisInput input) {
        String authorization = header(input.headers(), "authorization");
        if (authorization.regionMatches(true, 0, "Basic ", 0, 6) || authorization.regionMatches(true, 0, "Digest ", 0, 7))
            return new Auth(true, "Browser ambient Authorization authentication", List.of());
        String cookie = header(input.headers(), "cookie");
        List<String> all = new ArrayList<>(), likely = new ArrayList<>();
        for (String part : cookie.split(";")) {
            int equals = part.indexOf('=');
            if (equals <= 0) continue;
            String name = TrafficContext.normalize(part.substring(0, equals));
            all.add(name);
            if (AUTH_COOKIES.contains(name) || settings.customAuthCookies().contains(name)
                    || name.contains("sess") || name.contains("login") || name.contains("remember")) likely.add(name);
        }
        if (!likely.isEmpty()) return new Auth(true, "Likely session cookie: " + String.join(", ", likely), likely);
        if (!all.isEmpty() && settings.sensitivity() != CsrfSettings.Sensitivity.CONSERVATIVE)
            return new Auth(true, "Cookie authentication possible (cookie purpose unknown)", all);
        if (authorization.toLowerCase(Locale.ROOT).startsWith("bearer ")) return new Auth(false, "Bearer-only authentication is not normally ambient", List.of());
        return new Auth(false, "No browser-ambient authentication identified", List.of());
    }

    private Token token(AnalysisInput input) {
        List<AnalysisInput.InputField> fields = new ArrayList<>(input.fields() == null ? List.of() : input.fields());
        Matcher matcher = JSON_FIELD.matcher(input.body() == null ? "" : input.body());
        while (matcher.find()) fields.add(new AnalysisInput.InputField(matcher.group(1), matcher.group(2), "body"));
        for (Map.Entry<String, String> entry : input.headers().entrySet()) fields.add(new AnalysisInput.InputField(entry.getKey(), entry.getValue(), "header"));
        for (AnalysisInput.InputField field : fields) {
            String name = TrafficContext.normalize(field.name());
            boolean known = TOKEN_NAMES.contains(name) || TOKEN_HEADERS.contains(name) || settings.customTokenNames().contains(name)
                    || context.isLearnedTokenName(input.host(), name) || TrafficContext.looksTokenName(name);
            if (!known) continue;
            if (field.location() != null && field.location().equalsIgnoreCase("COOKIE")) continue;
            String value = field.value() == null ? "" : field.value();
            if (name.equals("x_requested_with")) return new Token("Weak", name, "Non-simple X-Requested-With header observed; server validation unverified");
            if (value.isBlank() || value.length() < 8) return new Token("Weak", name, "CSRF-like field is blank or too short: " + name);
            return new Token("Observed", name, "CSRF token observed in " + field.location() + ": " + name + " (validation unverified)");
        }
        if (opaqueBody(input.contentType(), input.body())) return new Token("Unknown", "", "Token status unknown for unsupported/opaque body");
        return new Token("Missing", "", "No CSRF token was identified");
    }

    private String cookieDefense(AnalysisInput input, List<String> authCookies) {
        if (authCookies.isEmpty()) return "Unknown";
        List<String> values = authCookies.stream().map(name -> context.sameSite(input.host(), name)).map(String::toLowerCase).toList();
        if (values.stream().anyMatch(v -> v.equals("none") || v.equals("unspecified"))) return "SameSite=None/unspecified";
        if (values.stream().allMatch(v -> v.equals("strict"))) return "SameSite=Strict";
        if (values.stream().allMatch(v -> v.equals("strict") || v.equals("lax"))) return "SameSite=Lax/Strict";
        return "SameSite unknown";
    }

    private boolean sensitive(AnalysisInput input) {
        StringBuilder text = new StringBuilder(input.path() == null ? "" : input.path()).append(' ');
        for (AnalysisInput.InputField field : input.fields() == null ? List.<AnalysisInput.InputField>of() : input.fields()) text.append(field.name()).append(' ');
        Set<String> words = new HashSet<>(SENSITIVE); words.addAll(settings.customSensitiveWords());
        String normalized = text.toString().toLowerCase(Locale.ROOT).replace('-', '_');
        return words.stream().anyMatch(normalized::contains);
    }

    private static String exploitability(String method, String contentType, Map<String, String> headers) {
        if (method.equals("GET")) return "Browser-forgeable";
        String type = lower(contentType);
        boolean customHeader = headers.keySet().stream().map(TrafficContext::normalize)
                .anyMatch(name -> name.startsWith("x_") && !TOKEN_HEADERS.contains(name));
        if (customHeader) return "Reduced by custom header";
        if (type.contains("application/x-www-form-urlencoded") || type.contains("multipart/form-data") || type.contains("text/plain")) return "Browser-forgeable";
        if (type.contains("json") || type.contains("xml")) return "Reduced by Content-Type";
        return "Unknown";
    }

    private static String originEvidence(Map<String, String> headers) {
        boolean origin = !header(headers, "origin").isBlank(), referer = !header(headers, "referer").isBlank();
        if (origin && referer) return "Origin and Referer observed; validation unverified";
        if (origin) return "Origin observed; validation unverified";
        if (referer) return "Referer observed; validation unverified";
        return "Origin/Referer absent";
    }

    private static boolean staticAsset(String path) {
        int dot = path.lastIndexOf('.'); if (dot < 0) return false;
        String ext = path.substring(dot + 1).split("[?#]", 2)[0]; return STATIC_EXT.contains(ext);
    }
    private static boolean opaqueBody(String contentType, String body) {
        if (body == null || body.isBlank()) return false;
        String type = lower(contentType);
        return type.contains("octet-stream") || type.contains("protobuf") || type.contains("grpc");
    }
    private static boolean cookieMitigates(String method, String defense) {
        return defense.equals("SameSite=Strict") || (!method.equals("GET") && defense.equals("SameSite=Lax/Strict"));
    }
    private static String endpointKey(String method, String url, String path, String operation) {
        String host = "";
        try { host = url == null ? "" : Optional.ofNullable(URI.create(url).getHost()).orElse(""); } catch (IllegalArgumentException ignored) { }
        String clean = (path == null ? "/" : path).split("\\?", 2)[0].replaceAll("/[0-9]+(?=/|$)", "/{id}")
                .replaceAll("/(?i:[0-9a-f]{8}-[0-9a-f-]{27,})(?=/|$)", "/{id}");
        return lower(host) + "|" + method + "|" + clean + (operation.isBlank() ? "" : "|mutation:" + operation);
    }
    private static String header(Map<String, String> headers, String name) {
        if (headers == null) return "";
        for (Map.Entry<String, String> entry : headers.entrySet()) if (entry.getKey().equalsIgnoreCase(name)) return entry.getValue() == null ? "" : entry.getValue();
        return "";
    }
    private static String lower(String value) { return value == null ? "" : value.toLowerCase(Locale.ROOT); }
    private record Auth(boolean ambient, String detail, List<String> cookieNames) { }
    private record Token(String status, String name, String detail) { }
}
