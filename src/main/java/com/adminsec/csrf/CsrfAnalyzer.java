package com.adminsec.csrf;

import com.adminsec.csrf.model.*;
import com.google.gson.*;

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
            "x_csrf_token", "x_csrf", "x_xsrf_token", "x_srf_token", "x_requested_with", "requestverificationtoken", "csrf_token");
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
    private static final Set<String> UNSAFE_METHODS = Set.of("POST", "PUT", "PATCH", "DELETE");
    private static final Set<String> OVERRIDE_NAMES = Set.of("_method", "method", "http_method", "x_http_method_override");
    private static final List<String> NOISE_PATHS = List.of("/analytics", "/telemetry", "/metrics", "/health", "/heartbeat", "/beacon");
    private static final Pattern GRAPHQL_MUTATION = Pattern.compile("(?is)\\bmutation(?:\\s+([A-Za-z_][A-Za-z0-9_]*))?");
    private static final Set<String> PLACEHOLDERS = Set.of("undefined", "null", "false", "changeme", "placeholder", "token", "none");
    private final CsrfSettings settings;
    private final TrafficContext context;

    public CsrfAnalyzer(CsrfSettings settings, TrafficContext context) {
        this.settings = settings; this.context = context;
    }

    public Optional<Assessment> analyze(AnalysisInput input) {
        if (input == null || input.method() == null) return Optional.empty();
        String method = input.method().toUpperCase(Locale.ROOT);
        String host = lower(input.host());
        String path = input.path() == null ? "/" : input.path();
        String lowerPath = path.toLowerCase(Locale.ROOT);
        if (settings.ignoredHosts().stream().anyMatch(host::equals)
                || settings.ignoredPaths().stream().anyMatch(lowerPath::contains)) return Optional.empty();
        if (Set.of("HEAD", "OPTIONS", "TRACE").contains(method)) return Optional.empty();
        if (isWebSocketHandshake(input.headers())) return analyzeWebSocketHandshake(input, path);

        GraphQl graphQl = graphQl(input);
        Workflow workflow = workflow(input);
        MethodOverride override = methodOverride(input);
        boolean sensitive = sensitive(input) || workflow.relevant || override.unsafe() || graphQl.mutation;
        boolean unsafe = UNSAFE_METHODS.contains(method) || graphQl.mutation || override.unsafe();
        boolean stateChangingGet = method.equals("GET") && (sensitive || graphQl.mutation || graphQl.persistedUnknown);
        if ((staticAsset(lowerPath) || NOISE_PATHS.stream().anyMatch(lowerPath::contains))
                && !unsafe && !stateChangingGet) return Optional.empty();
        if (!unsafe && !stateChangingGet) return Optional.empty();

        Auth auth = authentication(input);
        if (!auth.ambient && !workflow.relevant && settings.sensitivity() == CsrfSettings.Sensitivity.CONSERVATIVE)
            return Optional.empty();
        if (!auth.ambient && !workflow.relevant && settings.sensitivity() == CsrfSettings.Sensitivity.BALANCED && !sensitive)
            return Optional.empty();
        if (workflow.relevant && !auth.ambient)
            auth = new Auth(false, workflow.label + " can be CSRF-relevant before authentication", List.of());

        Token token = token(input, workflow.oauthLike);
        String cookieDefense = cookieDefense(input, auth.cookieNames);
        String exploitability = exploitability(method, input.contentType());
        String origin = originEvidence(input);
        String fetchMetadata = fetchMetadataEvidence(input.headers());
        String cors = corsEvidence(input);
        String customHeaders = customHeaderEvidence(input.headers());
        boolean browserForgeable = exploitability.startsWith("Browser-forgeable");

        Priority priority;
        String confidence;
        List<String> reasons = new ArrayList<>();
        String actionType = graphQl.actionType();
        if (actionType.isBlank()) actionType = workflow.relevant ? workflow.label : sensitive ? "Sensitive state change" : "State change";
        reasons.add(graphQl.reason().isBlank() ? method + (sensitive ? " request targets a sensitive action" : " may change server state") : graphQl.reason());
        if (override.present) reasons.add("Method override requests " + override.method + "; server handling is unverified");
        reasons.add(auth.detail);
        reasons.add(token.detail);
        reasons.add("Browser exploitability: " + exploitability);
        if (!customHeaders.isBlank()) reasons.add(customHeaders);
        reasons.add("Cookie defense: " + cookieDefense);
        reasons.add("Fetch Metadata: " + fetchMetadata);
        reasons.add("CORS: " + cors);

        if (token.status.equals("Observed")) {
            priority = Priority.PROTECTED;
            confidence = "Medium";
        } else if (token.status.equals("Weak")) {
            priority = Priority.REVIEW_2;
            confidence = "Medium";
        } else if (workflow.relevant && browserForgeable) {
            priority = Priority.REVIEW_1;
            confidence = token.status.equals("Missing") ? "High" : "Medium";
        } else if (workflow.relevant) {
            priority = Priority.REVIEW_2;
            confidence = "Medium";
        } else if (!auth.ambient) {
            priority = Priority.REVIEW_3;
            confidence = "Low";
        } else if (sensitive && browserForgeable && !cookieMitigates(method, cookieDefense)) {
            priority = Priority.REVIEW_1;
            confidence = token.status.equals("Missing") ? "High" : "Medium";
        } else {
            priority = Priority.REVIEW_2;
            confidence = token.status.equals("Missing") ? "Medium" : "Low";
        }

        String operationKey = graphQl.mutation ? "mutation:" + graphQl.operation
                : graphQl.persistedUnknown ? "graphql:" + graphQl.operation : "";
        return Optional.of(new Assessment(endpointKey(method, input.url(), input.host(), path, operationKey), actionType,
                auth.detail, auth.ambient, token.detail, token.name, origin, fetchMetadata, cors,
                cookieDefense, exploitability, priority, confidence, List.copyOf(reasons)));
    }

    private Optional<Assessment> analyzeWebSocketHandshake(AnalysisInput input, String path) {
        Auth auth = authentication(input);
        if (!auth.ambient && settings.sensitivity() == CsrfSettings.Sensitivity.CONSERVATIVE) return Optional.empty();
        Token token = token(input, false);
        String cookieDefense = cookieDefense(input, auth.cookieNames);
        String origin = originEvidence(input);
        String fetchMetadata = fetchMetadataEvidence(input.headers());
        String cors = "CORS does not govern WebSocket handshakes; Origin enforcement is unverified";
        String exploitability = "Browser WebSocket API can initiate a cross-site handshake; Origin enforcement is unverified";
        Priority priority;
        String confidence;
        if (token.status.equals("Observed")) {
            priority = Priority.PROTECTED; confidence = "Medium";
        } else if (token.status.equals("Weak")) {
            priority = Priority.REVIEW_2; confidence = "Medium";
        } else if (!auth.ambient) {
            priority = Priority.REVIEW_3; confidence = "Low";
        } else if (!cookieMitigatesWebSocket(cookieDefense)) {
            priority = Priority.REVIEW_1; confidence = token.status.equals("Missing") ? "High" : "Medium";
        } else {
            priority = Priority.REVIEW_2; confidence = "Medium";
        }
        List<String> reasons = List.of(
                "WebSocket upgrade uses browser-ambient credentials and requires CSWSH review",
                auth.detail, token.detail, "Origin evidence: " + origin,
                "Cookie defense: " + cookieDefense, "Fetch Metadata: " + fetchMetadata,
                "CORS: " + cors);
        return Optional.of(new Assessment(endpointKey("WS", input.url(), input.host(), path, ""),
                "WebSocket CSWSH handshake", auth.detail, auth.ambient, token.detail, token.name,
                origin, fetchMetadata, cors, cookieDefense, exploitability, priority, confidence, reasons));
    }

    private Auth authentication(AnalysisInput input) {
        String authorization = header(input.headers(), "authorization");
        if (authorization.regionMatches(true, 0, "Basic ", 0, 6)
                || authorization.regionMatches(true, 0, "Digest ", 0, 7))
            return new Auth(true, "Browser ambient Authorization authentication", List.of());
        String cookie = header(input.headers(), "cookie");
        List<String> all = new ArrayList<>(), likely = new ArrayList<>();
        for (String part : cookie.split(";")) {
            int equals = part.indexOf('=');
            if (equals <= 0 || part.substring(equals + 1).trim().isBlank()) continue;
            String name = TrafficContext.normalize(part.substring(0, equals));
            all.add(name);
            if (AUTH_COOKIES.contains(name) || settings.customAuthCookies().contains(name)
                    || name.contains("sess") || name.contains("login") || name.contains("remember")) likely.add(name);
        }
        if (!likely.isEmpty()) return new Auth(true, "Likely session cookie: " + String.join(", ", likely), likely);
        if (!all.isEmpty() && settings.sensitivity() != CsrfSettings.Sensitivity.CONSERVATIVE)
            return new Auth(true, "Cookie authentication possible (cookie purpose unknown)", all);
        if (authorization.toLowerCase(Locale.ROOT).startsWith("bearer "))
            return new Auth(false, "Bearer-only authentication is not normally ambient", List.of());
        return new Auth(false, "No browser-ambient authentication identified", List.of());
    }

    private Token token(AnalysisInput input, boolean oauthLike) {
        List<AnalysisInput.InputField> fields = new ArrayList<>(input.fields() == null ? List.of() : input.fields());
        addJsonFields(input.body(), fields);
        for (Map.Entry<String, String> entry : safeMap(input.headers()).entrySet())
            fields.add(new AnalysisInput.InputField(entry.getKey(), entry.getValue(), "HEADER"));

        Token weak = null;
        for (AnalysisInput.InputField field : fields) {
            String name = TrafficContext.normalize(field.name());
            boolean oauthToken = oauthLike && (name.equals("state") || name.equals("relaystate") || name.equals("relay_state"));
            boolean known = TOKEN_NAMES.contains(name) || TOKEN_HEADERS.contains(name)
                    || settings.customTokenNames().contains(name) || context.isLearnedTokenName(input.host(), name)
                    || TrafficContext.looksTokenName(name) || oauthToken;
            if (!known || isCookieLocation(field.location())) continue;
            String value = field.value() == null ? "" : field.value();
            if (name.equals("x_requested_with")) {
                weak = new Token("Weak", name, "X-Requested-With observed; server enforcement is unverified");
                continue;
            }
            if (value.isBlank() || value.length() < 8 || PLACEHOLDERS.contains(value.toLowerCase(Locale.ROOT))) {
                weak = new Token("Weak", name, "CSRF-like field is blank, short, or placeholder-like: " + name);
                continue;
            }
            String pair = matchingCookieValue(input.headers(), name, value)
                    ? " Possible double-submit cookie pair observed; signing/session binding is unverified."
                    : "";
            return new Token("Observed", name, "CSRF token observed in " + field.location() + ": " + name
                    + " (validation unverified)." + pair);
        }
        if (weak != null) return weak;
        if (opaqueBody(input.contentType(), input.body()))
            return new Token("Unknown", "", "Token status unknown for unsupported/opaque body");
        return new Token("Missing", "", "No CSRF token was identified");
    }

    private String cookieDefense(AnalysisInput input, List<String> authCookies) {
        if (authCookies.isEmpty()) return "Unknown";
        List<String> values = authCookies.stream()
                .map(name -> context.sameSite(input.url(), input.host(), input.path(), name))
                .map(String::toLowerCase).toList();
        if (values.stream().anyMatch(value -> value.equals("none") || value.equals("unspecified")))
            return "SameSite=None/unspecified";
        if (values.stream().anyMatch(value -> value.equals("unknown"))) return "SameSite unknown";
        if (values.stream().allMatch(value -> value.equals("strict"))) return "SameSite=Strict";
        if (values.stream().anyMatch(value -> value.equals("lax"))) return "SameSite=Lax/Strict";
        return "SameSite unknown";
    }

    private boolean sensitive(AnalysisInput input) {
        StringBuilder text = new StringBuilder(input.path() == null ? "" : input.path()).append(' ');
        for (AnalysisInput.InputField field : input.fields() == null ? List.<AnalysisInput.InputField>of() : input.fields())
            text.append(field.name()).append(' ');
        Set<String> words = new HashSet<>(SENSITIVE);
        words.addAll(settings.customSensitiveWords());
        String normalized = CsrfSettings.normalizeSensitiveText(text.toString());
        return words.stream().filter(word -> !word.isBlank()).anyMatch(normalized::contains);
    }

    private static String exploitability(String method, String contentType) {
        if (method.equals("GET")) return "Browser-forgeable";
        if (!method.equals("POST")) return "Reduced by non-simple method (CORS/preflight review required)";
        String type = lower(contentType);
        if (type.contains("application/x-www-form-urlencoded") || type.contains("multipart/form-data"))
            return "Browser-forgeable";
        if (type.contains("text/plain")) return "Browser-forgeable shape; exact payload compatibility unverified";
        if (type.contains("json") || type.contains("xml")) return "Reduced by non-simple Content-Type";
        if (type.isBlank()) return "Unknown (Content-Type absent)";
        return "Reduced by non-simple Content-Type";
    }

    private static String originEvidence(AnalysisInput input) {
        String origin = header(input.headers(), "origin"), referer = header(input.headers(), "referer");
        if (origin.equalsIgnoreCase("null")) return "Origin: null observed; validation unverified";
        if (!origin.isBlank()) return sourceRelation("Origin", origin, input.url());
        if (!referer.isBlank()) return sourceRelation("Referer", referer, input.url());
        return "Origin/Referer absent";
    }

    private static String sourceRelation(String name, String source, String target) {
        Optional<String> sourceOrigin = normalizedOrigin(source), targetOrigin = normalizedOrigin(target);
        if (sourceOrigin.isPresent() && targetOrigin.isPresent()) {
            String relation = sourceOrigin.get().equals(targetOrigin.get()) ? "same-origin" : "cross-origin";
            return name + " " + relation + " observed; server validation unverified";
        }
        return name + " observed but could not be parsed; validation unverified";
    }

    private static String fetchMetadataEvidence(Map<String, String> headers) {
        String site = header(headers, "sec-fetch-site"), mode = header(headers, "sec-fetch-mode");
        String dest = header(headers, "sec-fetch-dest"), user = header(headers, "sec-fetch-user");
        if (site.isBlank() && mode.isBlank() && dest.isBlank() && user.isBlank()) return "not observed";
        List<String> values = new ArrayList<>();
        if (!site.isBlank()) values.add("Site=" + site);
        if (!mode.isBlank()) values.add("Mode=" + mode);
        if (!dest.isBlank()) values.add("Dest=" + dest);
        if (!user.isBlank()) values.add("User=" + user);
        return String.join(", ", values) + "; enforcement unverified";
    }

    private static String corsEvidence(AnalysisInput input) {
        String allowOrigin = header(input.responseHeaders(), "access-control-allow-origin");
        String credentials = header(input.responseHeaders(), "access-control-allow-credentials");
        if (allowOrigin.isBlank()) return "no Access-Control-Allow-Origin observed";
        StringBuilder evidence = new StringBuilder("Allow-Origin=").append(allowOrigin);
        if (!credentials.isBlank()) evidence.append(", Allow-Credentials=").append(credentials);
        if (allowOrigin.equals("*") && credentials.equalsIgnoreCase("true"))
            evidence.append(" (credentialed wildcard is rejected by browsers)");
        else if (credentials.equalsIgnoreCase("true"))
            evidence.append(" (credentialed cross-origin access may be possible for the allowed origin)");
        return evidence.append("; preflight policy unverified").toString();
    }

    private static String customHeaderEvidence(Map<String, String> headers) {
        Set<String> ignored = Set.of("accept", "accept-language", "content-language", "content-type", "host",
                "cookie", "origin", "referer", "user-agent", "connection", "content-length", "accept-encoding",
                "authorization", "cache-control", "pragma");
        List<String> names = safeMap(headers).keySet().stream()
                .filter(Objects::nonNull).filter(name -> !name.toLowerCase(Locale.ROOT).startsWith("sec-"))
                .filter(name -> !ignored.contains(name.toLowerCase(Locale.ROOT)))
                .sorted(String.CASE_INSENSITIVE_ORDER).toList();
        return names.isEmpty() ? "" : "Non-safelisted request headers observed: " + String.join(", ", names)
                + "; whether the server requires them is unverified";
    }

    private static Workflow workflow(AnalysisInput input) {
        String normalizedPath = CsrfSettings.normalizeSensitiveText(input.path());
        Set<String> fieldNames = new HashSet<>();
        for (AnalysisInput.InputField field : input.fields() == null ? List.<AnalysisInput.InputField>of() : input.fields())
            fieldNames.add(TrafficContext.normalize(field.name()));
        boolean explicitOauthPath = containsAny(normalizedPath, "oauth", "oidc", "saml", "authorize", "connect_account", "link_account");
        boolean callbackWithProtocolFields = normalizedPath.contains("callback")
                && fieldNames.stream().anyMatch(Set.of("state", "relaystate", "authorization_code", "code")::contains);
        boolean oauth = explicitOauthPath || callbackWithProtocolFields
                || (fieldNames.contains("client_id") && fieldNames.contains("redirect_uri"));
        boolean loginPath = containsAny(normalizedPath, "login", "signin", "sign_in", "authenticate", "logon");
        boolean credentials = fieldNames.stream().anyMatch(Set.of("password", "passwd", "username", "email")::contains);
        if (oauth) return new Workflow(true, true, "OAuth/OIDC/SAML authorization workflow");
        if (loginPath && credentials) return new Workflow(true, false, "Login workflow");
        return new Workflow(false, false, "");
    }

    private static MethodOverride methodOverride(AnalysisInput input) {
        for (AnalysisInput.InputField field : input.fields() == null ? List.<AnalysisInput.InputField>of() : input.fields()) {
            String name = TrafficContext.normalize(field.name());
            String value = field.value() == null ? "" : field.value().toUpperCase(Locale.ROOT);
            if (OVERRIDE_NAMES.contains(name) && UNSAFE_METHODS.contains(value)) return new MethodOverride(true, value);
        }
        String value = header(input.headers(), "x-http-method-override").toUpperCase(Locale.ROOT);
        return UNSAFE_METHODS.contains(value) ? new MethodOverride(true, value) : new MethodOverride(false, "");
    }

    private static GraphQl graphQl(AnalysisInput input) {
        List<String> queries = new ArrayList<>();
        String operationName = "anonymous";
        boolean persisted = false, batched = false;
        for (AnalysisInput.InputField field : input.fields() == null ? List.<AnalysisInput.InputField>of() : input.fields()) {
            String name = TrafficContext.normalize(field.name());
            if (name.equals("query") && field.value() != null) queries.add(field.value());
            if (name.equals("operationname") && field.value() != null && !field.value().isBlank()) operationName = safeOperationName(field.value());
            if (name.equals("extensions") && lower(field.value()).contains("persistedquery")) persisted = true;
        }
        String body = input.body() == null ? "" : input.body().trim();
        if (!body.isBlank()) {
            try {
                JsonElement root = JsonParser.parseString(body);
                batched = root.isJsonArray();
                List<JsonObject> operations = new ArrayList<>();
                if (root.isJsonObject()) operations.add(root.getAsJsonObject());
                else if (root.isJsonArray()) for (JsonElement item : root.getAsJsonArray()) if (item.isJsonObject()) operations.add(item.getAsJsonObject());
                for (JsonObject operation : operations) {
                    JsonElement query = operation.get("query");
                    if (query != null && query.isJsonPrimitive() && query.getAsJsonPrimitive().isString()) queries.add(query.getAsString());
                    JsonElement name = operation.get("operationName");
                    if (name != null && name.isJsonPrimitive() && !name.getAsString().isBlank()) operationName = safeOperationName(name.getAsString());
                    JsonElement extensions = operation.get("extensions");
                    if (extensions != null && lower(extensions.toString()).contains("persistedquery")) persisted = true;
                }
            } catch (JsonParseException | IllegalStateException ignored) {
                queries.add(body);
            }
        }
        for (String query : queries) {
            Matcher matcher = GRAPHQL_MUTATION.matcher(query);
            if (matcher.find()) {
                String name = matcher.group(1) == null ? operationName : safeOperationName(matcher.group(1));
                return new GraphQl(true, false, name, "GraphQL mutation: " + name,
                        "GraphQL mutation changes server state");
            }
        }
        boolean graphQlEndpoint = lower(input.path()).contains("graphql");
        if (graphQlEndpoint && (persisted || batched)) {
            String kind = persisted ? "persisted" : "batched";
            return new GraphQl(false, true, operationName, "GraphQL " + kind + " operation (type unknown)",
                    "GraphQL " + kind + " operation requires manual state-change review");
        }
        return new GraphQl(false, false, "", "", "");
    }

    private static void addJsonFields(String body, List<AnalysisInput.InputField> fields) {
        if (body == null || body.isBlank()) return;
        try { collectJson(JsonParser.parseString(body), "", fields, 0); }
        catch (JsonParseException | IllegalStateException ignored) { }
    }
    private static void collectJson(JsonElement element, String name, List<AnalysisInput.InputField> fields, int depth) {
        if (element == null || depth > 32) return;
        if (element.isJsonObject()) {
            for (Map.Entry<String, JsonElement> entry : element.getAsJsonObject().entrySet())
                collectJson(entry.getValue(), entry.getKey(), fields, depth + 1);
        } else if (element.isJsonArray()) {
            for (JsonElement item : element.getAsJsonArray()) collectJson(item, name, fields, depth + 1);
        } else if (!name.isBlank() && element.isJsonPrimitive()) {
            fields.add(new AnalysisInput.InputField(name, element.getAsString(), "JSON"));
        }
    }

    private static boolean matchingCookieValue(Map<String, String> headers, String tokenName, String tokenValue) {
        for (String part : header(headers, "cookie").split(";")) {
            int equals = part.indexOf('=');
            if (equals <= 0) continue;
            if (TrafficContext.normalize(part.substring(0, equals)).equals(tokenName)
                    && part.substring(equals + 1).trim().equals(tokenValue)) return true;
        }
        return false;
    }
    private static boolean isCookieLocation(String location) {
        return location != null && location.toUpperCase(Locale.ROOT).contains("COOKIE");
    }
    private static boolean containsAny(String text, String... needles) {
        for (String needle : needles) if (text.contains(needle)) return true;
        return false;
    }
    private static boolean staticAsset(String path) {
        int dot = path.lastIndexOf('.');
        if (dot < 0) return false;
        String ext = path.substring(dot + 1).split("[?#]", 2)[0];
        return STATIC_EXT.contains(ext);
    }
    private static boolean opaqueBody(String contentType, String body) {
        if (body == null || body.isBlank()) return false;
        String type = lower(contentType);
        return type.contains("octet-stream") || type.contains("protobuf") || type.contains("grpc");
    }
    private static boolean cookieMitigates(String method, String defense) {
        return defense.equals("SameSite=Strict") || (!method.equals("GET") && defense.equals("SameSite=Lax/Strict"));
    }
    private static boolean cookieMitigatesWebSocket(String defense) {
        return defense.equals("SameSite=Strict") || defense.equals("SameSite=Lax/Strict");
    }
    private static boolean isWebSocketHandshake(Map<String, String> headers) {
        return header(headers, "upgrade").equalsIgnoreCase("websocket")
                || !header(headers, "sec-websocket-key").isBlank();
    }
    private static String endpointKey(String method, String url, String fallbackHost, String path, String operationKey) {
        String host = "";
        try {
            URI uri = URI.create(url == null ? "" : url);
            String parsedHost = Optional.ofNullable(uri.getHost()).orElse("");
            if (!parsedHost.isBlank()) {
                host = parsedHost + (uri.getPort() < 0 ? "" : ":" + uri.getPort());
            }
        }
        catch (IllegalArgumentException ignored) { }
        if (host.isBlank()) host = fallbackHost == null ? "" : fallbackHost;
        String clean = (path == null ? "/" : path).split("\\?", 2)[0]
                .replaceAll("/[0-9]+(?=/|$)", "/{id}")
                .replaceAll("/(?i:[0-9a-f]{8}-[0-9a-f-]{27,})(?=/|$)", "/{id}");
        if (clean.length() > 2_048) clean = clean.substring(0, 2_048) + "…";
        return lower(host) + "|" + method + "|" + clean + (operationKey.isBlank() ? "" : "|" + operationKey);
    }
    private static String safeOperationName(String value) {
        if (value == null || !value.matches("[A-Za-z_][A-Za-z0-9_]{0,127}")) return "anonymous";
        return value;
    }
    private static Optional<String> normalizedOrigin(String value) {
        try {
            URI uri = URI.create(value);
            if (uri.getScheme() == null || uri.getHost() == null) return Optional.empty();
            int port = uri.getPort();
            if (port < 0) port = uri.getScheme().equalsIgnoreCase("https") ? 443 : uri.getScheme().equalsIgnoreCase("http") ? 80 : -1;
            return Optional.of(uri.getScheme().toLowerCase(Locale.ROOT) + "://" + uri.getHost().toLowerCase(Locale.ROOT) + ":" + port);
        } catch (IllegalArgumentException ignored) { return Optional.empty(); }
    }
    private static String header(Map<String, String> headers, String name) {
        for (Map.Entry<String, String> entry : safeMap(headers).entrySet())
            if (entry.getKey() != null && entry.getKey().equalsIgnoreCase(name)) return entry.getValue() == null ? "" : entry.getValue();
        return "";
    }
    private static Map<String, String> safeMap(Map<String, String> map) { return map == null ? Map.of() : map; }
    private static String lower(String value) { return value == null ? "" : value.toLowerCase(Locale.ROOT); }

    private record Auth(boolean ambient, String detail, List<String> cookieNames) { }
    private record Token(String status, String name, String detail) { }
    private record Workflow(boolean relevant, boolean oauthLike, String label) { }
    private record MethodOverride(boolean present, String method) {
        boolean unsafe() { return present && UNSAFE_METHODS.contains(method); }
    }
    private record GraphQl(boolean mutation, boolean persistedUnknown, String operation, String actionType, String reason) { }
}
