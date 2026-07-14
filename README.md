# CSRF Review Assistant

CSRF Review Assistant is a passive-by-default, evidence-driven Burp Suite extension for finding requests that deserve manual CSRF testing. It supports Burp Suite Community and Professional, uses the Montoya API, and never sends a test request automatically. Guarded active verification is available only after explicit opt-in and two confirmations.

The extension deliberately reports **review candidates**, not confirmed vulnerabilities. A missing parameter named `csrf` is not enough to prove CSRF: the analyzer also considers browser-ambient authentication, action sensitivity, request content type, GraphQL mutations, observed token signals, Origin/Referer evidence, and SameSite cookie attributes.

## Features

- Inspects live Proxy traffic and up to 10,000 recent history items, in Target Scope by default; other Burp tools can be enabled explicitly.
- Finds tokens in URL/form/multipart/JSON/XML/GraphQL parameters and request headers.
- Learns host-scoped custom token names from hidden HTML/meta nonce fields.
- Separates Cookie or Basic/Digest authentication from normally non-ambient Bearer authentication.
- Detects sensitive unsafe methods, method overrides, state-changing GETs, login/OAuth CSRF workflows, GraphQL mutations, and persisted/batched GraphQL operations.
- Passively reviews WebSocket upgrade handshakes for Cross-Site WebSocket Hijacking (CSWSH).
- Records Origin relationships, Fetch Metadata, credentialed CORS signals, Content-Type/method barriers, and path/domain-scoped SameSite evidence without claiming enforcement.
- Uses P1/P2/P3 review priorities and keeps protected-looking traffic visible as `Protection observed`.
- Opens control, token-removal, empty/random-token, cross-site header, and JSON/XML-to-text/plain variants in Repeater without sending them.
- Generates an offline HTML PoC only for GET and URL-encoded POST shapes that HTML forms can represent without changing method or parameter location.
- Offers guarded active verification only when enabled: Target Scope is mandatory, variants are selected manually, confirmation is repeated, the control is not resent, and redirects are not followed.
- Caps retained candidates, stores retained HTTP messages in Burp temporary files, batches UI updates, and provides history scan progress/cancellation.
- Saves review state and notes in the Burp project; raw messages and secrets are not copied into extension persistence.
- Exports redacted JSON, CSV, or HTML reports without raw requests, Cookie/Authorization values, or token values; reviewer notes are omitted by default.
- Adds an informational/tentative passive Scanner issue for P1 candidates when Scanner is available.

## Build

Java 17 or later is required. A Gradle wrapper is included:

```bash
./gradlew clean test jar
```

The loadable artifact is:

```text
build/libs/csrf-review-assistant-1.1.0.jar
```

GitHub Actions runs the tests and publishes this JAR as a directly downloadable workflow artifact. Attach the tested JAR to a versioned GitHub Release for normal end-user downloads; do not commit the local `build/` directory.

## Install and use

1. In Burp, open **Extensions > Installed > Add**.
2. Select extension type **Java** and load the JAR above.
3. Put authorized targets in **Target > Scope**.
4. Browse the application normally, then open the **CSRF Review** tab.
5. Start with P1 candidates. Read **Why flagged**, create Repeater variants, and verify both the response and the real server-side state.
6. Mark each row as Protected, Confirmed, False Positive, or another review state.

Generated Repeater tabs are inert until the user presses **Send**. Requests that change passwords, email addresses, permissions, payments, or data can be destructive; use test accounts and understand the action before sending anything.

Guarded active verification is disabled by default. If enabled, it still cannot confirm a CSRF vulnerability from status/body similarity alone; verify the actual server-side state.

## Priority model

- **P1:** likely browser-ambient authentication, sensitive action, browser-forgeable request, and no identified token or strong observed cookie barrier.
- **P2:** missing/weak token with a non-simple method/Content-Type, SameSite evidence, or another uncertain barrier; manual review is still useful.
- **P3:** authentication or state-change evidence is uncertain. Hidden by the conservative policy and available in broader sensitivity modes.
- **Protection observed:** a token-like defense is present, but passive analysis cannot prove that the server validates it correctly.

`Origin` or `Referer` appearing in a request is never treated as proof of enforcement. Likewise, SameSite is defense-in-depth and may be bypassable in same-site scenarios.

## Settings and privacy

The default policy is **Conservative**, **Target Scope only**, Proxy-only capture, a 5,000-candidate cap, notes excluded from exports, and active verification disabled. Active verification is session-only and must be re-enabled after every extension load. Settings allow Unicode sensitive words, custom token/authentication-cookie names, exclusions, history/body/candidate limits, optional non-Proxy tool capture, and Balanced/Aggressive discovery.

There is no telemetry, AI provider, cloud service, or update check. Passive analysis makes no network request. Only explicitly confirmed guarded verification sends selected requests to an in-scope target. The extension stores settings, review status, and bounded reviewer notes; exports are metadata-only and omit notes by default.

## Limitations

- Passive evidence cannot establish whether a server accepts a forged request; manual verification is always required.
- A session cookie with an unusual name may need to be added to the authentication-cookie setting.
- Opaque/protobuf/gRPC bodies are reported as unknown rather than parsed heuristically.
- HTML PoCs are not generated for multipart, JSON, XML, WebSocket, custom-header, or non-GET/POST requests because converting them can be misleading.
- Passive evidence, including an observed token, Fetch Metadata, Origin, or SameSite attribute, cannot prove server-side enforcement.
- WebSocket support reviews the upgrade handshake; it does not actively replay application messages.

See [GUIDE_AR.md](GUIDE_AR.md) for the Arabic usage guide.

## License

MIT. See [LICENSE](LICENSE). Runtime dependency notices are listed in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
