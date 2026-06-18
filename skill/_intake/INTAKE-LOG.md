# Media Intake Log

Every video / short / image / thread you send is processed per `../MEDIA-INTAKE.md`
and gets ONE row here — including "already covered" — so nothing is ever silently
dropped. Drop media in `_intake/media/` (gitignored) or just paste it.

| Date | Source (your one-liner / link) | Extracted control | Outcome | Where it landed |
|---|---|---|---|---|
| 2026-06-18 | (system bootstrap — not media) | — | Engine + 52-check registry built from the 6 reference docs; runner + forced protocol + 7 seed templates | `engine/registry.yaml` |
| 2026-06-18 | reel1 `DZsXW-HonCi` "your login isn't secure" (5 items) | localStorage token · client-side admin check · 2FA/email-verify · auth+reset rate-limit · password policy/leaked-check | 4 new checks (rate-limit already covered) | AUTH-STORAGE-001 · AUTHZ-SERVER-001 · ACCT-VERIFY-001 · PWPOLICY-001 (RATE-001/LOCK-001 existed) |
| 2026-06-18 | reel2 `DYSNDBqic3r` testing pyramid | unit→integration→e2e pyramid | methodology, not a check | `references/security-testing-methodology.md` §10 |
| 2026-06-18 | reel3 `DYU_8ZcEmLl` stubs vs mocks | stub (canned data) vs mock (assert interaction) | methodology, not a check | `references/security-testing-methodology.md` §10 |
| 2026-06-18 | reel4 `DZU-RaVRCrt` (PT) frontend cybersecurity | NEXT_PUBLIC env · source maps · cookie flags · localStorage/PII · CORS/CSP | 3 new checks (CORS/CSP existed) | CLIENT-ENV-001 · SOURCEMAP-001 · COOKIE-FLAGS-001 (+ AUTH-STORAGE-001) |
| 2026-06-18 | reel5 `DYDezT5xnIS` Postman unauth test + Supabase launch-guide TOC | unauth endpoint returns data · RLS = #1 Supabase gap · anon vs service_role · refresh rotation/logout | 3 new checks | AUTHN-REQUIRED-001 · SUPABASE-RLS-001 · TOKEN-ROTATE-001 (+ CLIENT-ENV-001) |
| 2026-06-18 | reel6 `DXz5iIwxiuF` "don't launch yet" 3 API exposures | open endpoints · no pagination · raw error messages | 3 new checks | AUTHN-REQUIRED-001 · PAGINATION-001 · ERRORLEAK-001 |
| 2026-06-18 | `mukul975/Anthropic-Cybersecurity-Skills` (754 skills, Apache-2.0) | app-sec techniques absent from registry + 5-framework mapping | 12 new checks + 2 reference docs + catalogue | XXE/SSTI/NOSQLI/REDIRECT/PATHTRAV/HOSTHDR/CLICKJACK/WEBSOCKET/EXCESSDATA/APIINV/OAUTH/CISEC-001 + `framework-mappings.md` + `cyber-skills-catalog.md` |

_Source media staged in `_intake/media/` (gitignored). Transcripts + frame montages were the extraction inputs (both, per the intake contract)._
