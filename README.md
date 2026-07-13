# CSRF Review Assistant

CSRF Review Assistant is a passive, evidence-driven Burp Suite extension for finding requests that deserve manual CSRF testing. It supports Burp Suite Community and Professional, uses the Montoya API, and never sends a test request automatically.

The extension deliberately reports **review candidates**, not confirmed vulnerabilities. A missing parameter named `csrf` is not enough to prove CSRF: the analyzer also considers browser-ambient authentication, action sensitivity, request content type, GraphQL mutations, observed token signals, Origin/Referer evidence, and SameSite cookie attributes.

## Features

- Inspects live Proxy traffic and up to 10,000 recent history items, in Target Scope by default.
- Finds tokens in URL/form/multipart/JSON/XML/GraphQL parameters and request headers.
- Learns host-scoped custom token names from hidden HTML/meta nonce fields.
- Separates Cookie or Basic/Digest authentication from normally non-ambient Bearer authentication.
- Detects sensitive unsafe methods, state-changing GET candidates, and GraphQL mutations.
- Records Origin, Referer, Fetch Metadata, Content-Type barriers, and SameSite as evidence without claiming server validation.
- Uses P1/P2/P3 review priorities and keeps protected-looking traffic visible as `Protection observed`.
- Opens control, token-removal, empty/random-token, and cross-site header variants in Repeater without sending them.
- Generates an offline HTML PoC only for request shapes that can be represented reliably.
- Saves review state and notes in the Burp project; raw messages and secrets are not copied into extension persistence.
- Exports redacted JSON, CSV, or HTML reports without raw requests, Cookie/Authorization values, or token values.
- Adds an informational/tentative passive Scanner issue for P1 candidates when Scanner is available.

## Build

Java 17 or later is required. A Gradle wrapper is included:

```bash
./gradlew clean test jar
```

The loadable artifact is:

```text
build/libs/csrf-review-assistant-1.0.0.jar
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

## Priority model

- **P1:** likely browser-ambient authentication, sensitive action, browser-forgeable request, and no identified token or strong observed cookie barrier.
- **P2:** missing/weak token with a possible JSON, custom-header, or SameSite barrier; manual review is still useful.
- **P3:** authentication or state-change evidence is uncertain. Hidden by the conservative policy and available in broader sensitivity modes.
- **Protection observed:** a token-like defense is present, but passive analysis cannot prove that the server validates it correctly.

`Origin` or `Referer` appearing in a request is never treated as proof of enforcement. Likewise, SameSite is defense-in-depth and may be bypassable in same-site scenarios.

## Settings and privacy

The default policy is **Conservative** and **Target Scope only**. Settings allow custom token names, authentication cookie names, sensitive action words, host/path exclusions, history limits, body limits, and Balanced/Aggressive discovery.

There is no telemetry, AI provider, cloud service, or external network request. The extension stores only settings, review status, and reviewer notes. Reports are metadata-only and intentionally omit raw HTTP messages and secret values.

## Limitations

- Passive evidence cannot establish whether a server accepts a forged request; manual verification is always required.
- A session cookie with an unusual name may need to be added to the authentication-cookie setting.
- Opaque/protobuf/gRPC bodies are reported as unknown rather than parsed heuristically.
- HTML PoCs are not generated for JSON/XML/custom-header requests because silently converting them can produce misleading tests.
- WebSocket CSWSH analysis is not part of version 1.0.

See [GUIDE_AR.md](GUIDE_AR.md) for the Arabic usage guide.

## License

MIT. See [LICENSE](LICENSE). Runtime dependency notices are listed in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
