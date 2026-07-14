# Changelog

## 1.1.0 — 2026-07-14

- Corrected browser-forgeability modeling for PUT/PATCH/DELETE, non-simple content types, and unrelated custom headers.
- Fixed offline PoCs so methods and URL/body parameter locations are never silently changed.
- Added Fetch Metadata, Origin relationship, credentialed CORS, login/OAuth, method-override, persisted/batched GraphQL, and WebSocket CSWSH evidence.
- Added Unicode-sensitive settings and path/domain-aware SameSite cookie observations.
- Added bounded temporary-file message retention, candidate limits, debounced UI refresh, scan progress/cancellation, and optional non-Proxy tool capture.
- Added disabled-by-default guarded active verification with scope enforcement, manual variant selection, double confirmation, no control resend, no redirects, and evidence-only results.
- Strengthened report redaction and made reviewer-note export opt-in.
- Upgraded dependencies and Gradle, and added dependency locks and SHA-256 verification metadata.
- Expanded automated coverage from 14 to 38 tests.

## 1.0.0 — 2026-07-13

- Initial evidence-driven passive CSRF analyzer.
- Community-compatible dashboard, filters, review workflow, and project persistence.
- Safe Repeater variant and offline HTML PoC generation.
- Redacted JSON, CSV, and HTML reporting.
- Optional informational/tentative Burp Scanner integration.
