# Framework Mappings — bedrock checks across the major security frameworks

> bedrock checks are anchored to **OWASP / CWE / RFC** oracles (the falsifiable
> "what correct means"). This doc adds the broader **compliance/threat** frameworks
> so a single sweep also speaks ATT&CK, NIST CSF, D3FEND, ATLAS, and AI RMF — the
> cross-framework layer mined from the `mukul975/Anthropic-Cybersecurity-Skills`
> corpus (Apache-2.0; see `cyber-skills-catalog.md` for attribution).
>
> New registry records may carry an optional `frameworks:` field, e.g.
> `frameworks: { nist_csf: [PR.AA], mitre_attack: [T1190] }`. The runner ignores it
> (it's documentation + future reporting); it does not change the gate.

## The five frameworks

| Framework | Scope | What it maps |
|---|---|---|
| MITRE ATT&CK v19 | adversary TTPs | the attacker behaviour a missing control enables |
| NIST CSF 2.0 | org posture | Govern / Identify / Protect / Detect / Respond / Recover |
| MITRE D3FEND | defensive countermeasures | the defensive technique a check implements |
| MITRE ATLAS | AI/ML adversarial threats | LLM/agent attack vectors (pairs with our `llm-ai` checks) |
| NIST AI RMF | AI risk management | trustworthy-AI controls (GenAI profile: prompt injection, etc.) |

## OWASP Top 10 → bedrock checks (the spine)

| OWASP (2021/2025) | bedrock checks | ATT&CK | NIST CSF |
|---|---|---|---|
| A01 Broken Access Control | BOLA-001, BFLA-001, MASS-001, AUTHN-REQUIRED-001, AUTHZ-SERVER-001, SUPABASE-RLS-001, PATHTRAV-001, REDIRECT-001, WEBSOCKET-001, TENANT-DEL-001, PATTERN-002 | T1078, T1548 | PR.AA |
| A02 Cryptographic Failures | FLOOR-A02, CLIENT-ENV-001, COOKIE-FLAGS-001, TIMING-001 | T1557, T1040 | PR.DS |
| A03 Injection | INJ-001, SSTI-001, NOSQLI-001, XXE-001, FLOOR-A03, REDOS-001 | T1190, T1059 | PR.DS, DE.AE |
| A04 Insecure Design | DEC-001, CSRF-001, the philosophy gates | T1195 | GV.RM, PR.PS |
| A05 Security Misconfiguration | HDR-001, HDR-002, CLICKJACK-001, SOURCEMAP-001, ERRORLEAK-001, FLOOR-A05, XXE-001 | T1574, T1190 | PR.PS, PR.IR |
| A06 Vulnerable Components | DEP-001, DEP-002, DEP-003, CISEC-001 | T1190, T1195 | ID.RA, GV.SC |
| A07 Identification & Auth Failures | JWT-001, JWT-002, LOCK-001, RATE-001, ACCT-VERIFY-001, PWPOLICY-001, TOKEN-ROTATE-001, OAUTH-001, AUTH-STORAGE-001 | T1110, T1539 | PR.AA |
| A08 Software/Data Integrity | FLOOR-A08, WEBHOOK-001, DEP-003, CISEC-001 | T1195, T1554 | PR.DS, GV.SC |
| A09 Logging & Monitoring Failures | FLOOR-A09, AUDIT-001, SEC-LEAK-001, ERRORLEAK-001 | T1070, T1562 | DE.CM, DE.AE |
| A10 SSRF | SSRF-001, HOSTHDR-001 | T1190 | PR.DS, DE.AE |

## OWASP API Security Top 10 (2023) → bedrock checks

| API risk | bedrock checks |
|---|---|
| API1 BOLA | BOLA-001, SUPABASE-RLS-001 |
| API2 Broken Authentication | JWT-001, JWT-002, AUTHN-REQUIRED-001, TOKEN-ROTATE-001 |
| API3 Broken Object Property Level Authz / excessive data | EXCESSDATA-001, MASS-001 |
| API4 Unrestricted Resource Consumption | RATE-001, PAGINATION-001, GRAPHQL (queued), SIZE-001 |
| API5 Broken Function Level Authz | BFLA-001, AUTHZ-SERVER-001 |
| API6 Unrestricted Access to Sensitive Business Flows | RATE-001, IDEM-001 |
| API7 SSRF | SSRF-001 |
| API8 Security Misconfiguration | HDR-001, HDR-002, CORS, CLICKJACK-001 |
| API9 Improper Inventory Management | APIINV-001 |
| API10 Unsafe Consumption of APIs | WEBHOOK-001, SSRF-001 |

## The real-world "pre-launch" crosswalk (from reel5's security guide TOC)

A creator's Supabase-focused launch guide (reel5 frames) lays out 7 sections; every
one maps to a bedrock check — a useful external validation that the engine covers a
practitioner's real checklist:

| Guide section | bedrock check(s) |
|---|---|
| 1.1 Cookie Configuration | COOKIE-FLAGS-001 |
| 1.2 Refresh Token Rotation · 1.4 Logout & Session Invalidation | TOKEN-ROTATE-001 |
| 1.3 Brute-Force Protection | LOCK-001, RATE-001 |
| 2.1 Route Protection | AUTHN-REQUIRED-001 |
| 2.2 RBAC | BFLA-001, AUTHZ-SERVER-001 |
| 2.3 Row Level Security ("#1 Supabase gap") | SUPABASE-RLS-001, BOLA-001 |
| 3.1 XSS · 3.2 SQLi (RPC/Edge) · 3.3 CSRF | INJ-001, FLOOR-A03, CSRF-001 |
| 4.1 Env vars (anon vs service_role) | CLIENT-ENV-001 |
| 4.2 HTTPS & HSTS · 4.3 CORS | HDR-001, HDR-002 |
| 4.4 Dependency & Package Security | DEP-001, CISEC-001 |
| 4.5 Rate Limiting · 4.6 Logging & Error Handling | RATE-001, ERRORLEAK-001, FLOOR-A09 |
| 5.x Supabase/OAuth/Next.js patterns | SUPABASE-RLS-001, OAUTH-001, CLIENT-ENV-001, SOURCEMAP-001 |

## AI/LLM frameworks (ATLAS + AI RMF) → bedrock `llm-ai` checks

| Threat | bedrock check | ATLAS | AI RMF |
|---|---|---|---|
| Prompt injection (direct/indirect) | LLM-INJ-001 | AML.T0051 | MEASURE-2.6 |
| Insecure output / data leak | LLM-OUT-001 | AML.T0057 | MEASURE-2.6 |
| Guard fail-open + kill switch | LLM-FAILOPEN-001 | — | MANAGE-2.1 |

These mappings are documentation aids, not new gates — the falsifiable oracle in each
record (OWASP/CWE/RFC) remains the thing a test proves.
