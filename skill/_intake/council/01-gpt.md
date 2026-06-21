# GPT Council Voice 1 — Opinionated Elevation Plan for `bedrock-security`

## 1. Top Gaps Blocking “Ultimate SaaS Security Tool”

### Gap 1 — The registry is a strong checklist, not yet an execution graph
The current 76-check table has `phase` values like `frame`, `static`, `adversarial`, `decision`, and `triage`, but it does not encode real dependencies.

Examples:
- `BOLA-001`, `BFLA-001`, `AUTHZ-SERVER-001`, `AUTHN-REQUIRED-001`, `EXCESSDATA-001`, `SUPABASE-RLS-001`, and `TENANT-DEL-001` all depend on `INV-001` and `INV-005`, but that dependency is only implied.
- `JWT-002` depends on `INV-002`; without enumerating every token type, the token-purpose test is incomplete.
- `SSRF-001`, `WEBHOOK-001`, `IDEM-001`, and `TIMING-001` depend on `INV-003`, but currently they appear as peer checks.
- `LLM-INJ-001`, `LLM-OUT-001`, and `LLM-FAILOPEN-001` depend on `INV-006`, plus a tool/function inventory that does not yet exist.
- `DEPLOY-GATE-001` and `INV-007` should gate any staging/prod probing, but the current flow does not make deploy-target confirmation a hard prerequisite.

The “ultimate” version needs a DAG: `check_id`, `requires`, `unlocks`, `blocks_if_fail`, `environment`, `tool`, `evidence_type`, and `safe_to_run_against_prod`.

---

### Gap 2 — Tool mapping is absent, so “static-scan” is underspecified
Many checks say `static-scan`, but not what implements them.

Examples:
- `SEC-LEAK-001` should explicitly run `gitleaks` and `trufflehog`, including git history.
- `DEP-001` should run `osv-scanner`, `npm audit`, `pip-audit`, `safety`, `cargo audit`, `go list -m -json | govulncheck`, and/or `trivy fs` depending on stack.
- `FLOOR-A03`, `PATTERN-004`, `FLOOR-A08`, `REDOS-001`, `COOKIE-FLAGS-001`, `CLIENT-ENV-001`, and `PATTERN-003` need `semgrep` rulesets and optional `CodeQL`.
- `HDR-001`, `HDR-002`, `CLICKJACK-001`, `SOURCEMAP-001`, and `ERRORLEAK-001` need live HTTP probes using `nuclei`, `httpx`, `curl`, `OWASP ZAP`, or custom Playwright checks.
- `SSRF-001` needs controlled callback infrastructure: `interactsh`, `Burp Collaborator`, or a self-hosted canary endpoint.

Without concrete tools, the runner cannot be truly executable beyond grep/manual proof.

---

### Gap 3 — Environment mapping is too vague
The current system mixes checks that belong in very different places.

Bad examples:
- `SEC-LEAK-001`, `ENV-001`, `ENV-002`, `DEP-002`, `DEP-003`, `PATTERN-003` should run before code leaves the developer machine and again in CI.
- `HDR-001`, `HDR-002`, `COOKIE-FLAGS-001`, `SOURCEMAP-001`, `CLICKJACK-001` cannot be fully proven statically; they need a running app, preferably ephemeral preview or staging.
- `RACE-001`, `RATE-001`, `LOCK-001`, `IDEM-001` are destructive/load-ish and should not run against prod except carefully designed prod-readonly/canary variants.
- `BOLA-001`, `BFLA-001`, `MASS-001`, `AUTHN-REQUIRED-001` need seeded identities and fixtures, which means ephemeral preview or staging, not random local static scanning.
- `SUPABASE-RLS-001` needs database introspection and transaction-wrapped SQL probes, ideally staging or a disposable database clone.
- `LLM-INJ-001` and `LLM-OUT-001` can burn tokens or trigger real actions; they need a mocked tool layer or staging model gateway first.

The tool should force “where can this safely run?” per check.

---

### Gap 4 — The flow starts with “run the engine” but not with “establish authority and safety”
For real SaaS work, the first gate is not scanning. It is permission, target identity, and blast-radius control.

Missing first-class gates:
- “Do we own this target?”
- “Which environment is authorized?”
- “Are test accounts seeded?”
- “Can the scanner send emails, payments, webhooks, model calls, or destructive mutations?”
- “Is there a rollback/snapshot?”
- “Are rate/load/concurrency tests capped?”
- “Is prod probing readonly only?”

`INV-007` and `DEPLOY-GATE-001` gesture toward this, but they should become a formal `SAFETY` stage before adversarial execution.

---

### Gap 5 — It is too application-centric; modern SaaS security is also cloud/IaC/identity/data
The current registry is strong on app-layer authz, JWT, injection, webhook, LLM, and abuse checks. It is weaker on:

- Cloud IAM and least privilege.
- Object storage exposure.
- Database backup/snapshot exposure.
- Kubernetes/container runtime posture.
- Terraform/IaC drift.
- CI secret exfiltration paths.
- SaaS admin-plane permissions.
- Data retention and deletion workflows.
- Observability pipelines leaking PII.
- Tenant-aware analytics/search/cache isolation.
- Background jobs and queues.
- Email/SMS abuse.
- Payment/billing provider hardening.
- Domain/DNS/email security: SPF, DKIM, DMARC, CAA.
- Incident readiness: alerting, runbooks, restore tests.

For “ultimate SaaS”, appsec is necessary but insufficient.

---

### Gap 6 — “Oracle” currently means standards reference, not proof oracle
The table’s `oracle` column mostly cites OWASP/CWE/RFC. That is useful, but not an executable oracle.

Example:
- `JWT-001` oracle says RFC 8725. The actual proof oracle should be:
  - unsigned token rejected;
  - `alg=none` rejected;
  - HS/RS confusion rejected;
  - expired token rejected;
  - missing `exp` rejected;
  - wrong `aud` rejected;
  - wrong `iss` rejected;
  - tampered signature rejected;
  - weak algorithm rejected;
  - protected endpoint returns 401, not 500.

Every check needs a machine-readable `pass_condition`, `fail_condition`, `evidence_schema`, and `negative_control`.

---

### Gap 7 — The table lacks asset criticality and business context
A SaaS security tool must distinguish:
- public marketing route;
- logged-in user route;
- admin route;
- billing route;
- webhook route;
- background job;
- LLM tool execution;
- data export route;
- tenant deletion route;
- support impersonation route.

Right now, severity is mostly fixed by check. But `BOLA-001` on `/profile/avatar` and `BOLA-001` on `/billing/invoices/:id` are not equal. The scanner needs asset labels and data classes.

---

### Gap 8 — No mature finding lifecycle
`TRIAGE-001` exists, but the system needs more:
- deduplication;
- suppressions with expiry;
- owner assignment;
- SLA by severity;
- regression test generated from finding;
- fix verification;
- reopen on recurrence;
- evidence retention;
- CI annotations;
- SARIF export;
- ticket export to GitHub/Jira/Linear.

The “ultimate” tool is not just a scanner; it is a security programme engine.

---

## 2. Right Order — Proposed Sequencing and Gates

## Stage 0 — Authorization, Scope, and Blast Radius

**Purpose:** prevent unsafe or unauthorized testing.

Run before everything:
1. `INV-007` — identify real deploy target and deploy mechanism.
2. `DEPLOY-GATE-001` — target confirmed, rollback known, smoke scripted.
3. New `SCOPE-001` — authorized targets, environments, accounts, rate caps.
4. New `DATA-SAFETY-001` — classify whether tests may mutate data, send email, hit payment, call LLM, or trigger webhooks.

**Gates:**
- No adversarial test runs until `INV-007` and `DEPLOY-GATE-001` pass.
- No concurrency/destructive tests until test data/rollback is confirmed.
- Prod defaults to readonly probes only.

---

## Stage 1 — Stack, Asset, Endpoint, Data, and Identity Inventory

**Purpose:** build the map. Everything else depends on it.

Run:
1. `INV-008` — detect stacks to select proof templates.
2. `INV-001` — enumerate every route/endpoint and auth mode.
3. `APIINV-001` — confirm no shadow/undocumented/legacy endpoints.
4. `INV-005` — enumerate data stores and tenancy model.
5. `INV-002` — enumerate auth modes and all JWT/token types.
6. `INV-003` — enumerate outbound/server-side fetches.
7. `INV-004` — enumerate secrets/env vars and sinks.
8. `INV-006` — enumerate LLM/AI surfaces.

**Dependencies created:**
- `INV-001` unlocks `AUTHN-REQUIRED-001`, `AUTHZ-SERVER-001`, `BOLA-001`, `BFLA-001`, `MASS-001`, `EXCESSDATA-001`, `PATHTRAV-001`, `REDIRECT-001`, `WEBSOCKET-001`, `INJ-001`, `PAGINATION-001`.
- `INV-005` unlocks `SUPABASE-RLS-001`, `TENANT-DEL-001`, `AUDIT-001`, `RACE-001`.
- `INV-002` unlocks `JWT-001`, `JWT-002`, `TOKEN-ROTATE-001`, `OAUTH-001`, `COOKIE-FLAGS-001`, `AUTH-STORAGE-001`, `ACCT-VERIFY-001`, `PWPOLICY-001`, `LOCK-001`.
- `INV-003` unlocks `SSRF-001`, `WEBHOOK-001`, `IDEM-001`, `TIMING-001`.
- `INV-004` unlocks `SEC-LEAK-001`, `ENV-001`, `ENV-002`, `PATTERN-003`, `FLOOR-A09`, `LLM-OUT-001`, `ERRORLEAK-001`.
- `INV-006` unlocks `LLM-INJ-001`, `LLM-OUT-001`, `LLM-FAILOPEN-001`.

**Wasted if done too early:**
- Running `BOLA-001` before `INV-001` causes endpoint gaps.
- Running `JWT-002` before `INV-002` misses reset/email/2FA tokens.
- Running `SSRF-001` before `INV-003` probes the wrong parameters.
- Running `LLM-INJ-001` before `INV-006` misses hidden model calls and agent tools.

---

## Stage 2 — Cheap Local Static Gates

**Purpose:** fail fast before spinning environments.

Run in pre-commit and CI:
1. `SEC-LEAK-001`
2. `ENV-001`
3. `ENV-002`
4. `PATTERN-003`
5. `DEP-002`
6. `DEP-003`
7. `FLOOR-A03`
8. `FLOOR-A08`
9. `PATTERN-004`
10. `REDOS-001`
11. `CLIENT-ENV-001`
12. `COOKIE-FLAGS-001`, partial static
13. `CISEC-001`
14. `TEST-ISO-001`, static/test config portion
15. `DOC-FRESH-001`

**Gates:**
- `SEC-LEAK-001` critical fail blocks all CI/deploy.
- `PATTERN-003` blocks deploy; default JWT secret is catastrophic.
- `DEP-003` should block for protected branches.
- `DEP-001` should block when exploitable/runtime/high-critical.

**Wasted if late:**
- Secret scanning after adversarial testing is backwards.
- Dependency checks after staging deploy are too late.
- Client env exposure after production build publication is too late.

---

## Stage 3 — Build Artifact, Container, and IaC Gates

**Purpose:** prove what will actually ship, not just source code.

Existing checks:
- `DEP-001`
- `FLOOR-A05`
- `FLOOR-A02`
- `SOURCEMAP-001`
- `CLIENT-ENV-001`
- `CISEC-001`

Additions needed:
- `CONTAINER-001` — base image CVEs and package vulnerabilities.
- `CONTAINER-002` — non-root user, read-only filesystem where possible, no privileged container.
- `SBOM-001` — generate SBOM.
- `SIGN-001` — sign artifact/container.
- `IAC-001` — Terraform/Kubernetes/cloud misconfig scan.
- `LICENSE-001` — license policy if commercial SaaS requires it.

**Gates:**
- Do not deploy preview/staging if image has critical reachable CVEs.
- Do not run HTTP security probes against a build that is not production-equivalent.

---

## Stage 4 — Ephemeral Preview Dynamic Baseline

**Purpose:** safe live HTTP/browser validation.

Run:
1. `HDR-001`
2. `HDR-002`
3. `CLICKJACK-001`
4. `COOKIE-FLAGS-001`
5. `SOURCEMAP-001`
6. `ERRORLEAK-001`
7. `AUTH-STORAGE-001`
8. `AUTHN-REQUIRED-001`
9. `AUTHZ-SERVER-001`
10. `EXCESSDATA-001`
11. `PAGINATION-001`
12. `PATHTRAV-001`
13. `REDIRECT-001`
14. `WEBSOCKET-001`
15. `SIZE-001`

**Gates:**
- `AUTHN-REQUIRED-001` should run before `BOLA-001`; if anonymous users can access the data endpoint, object authz testing is secondary.
- Header/CORS/cookie checks should run before heavier adversarial suites because they are cheap and quickly expose environment misconfiguration.
- `SIZE-001` should run before broad fuzzing to prevent accidental scanner-induced denial of service.

---

## Stage 5 — Seeded Identity and Tenant Adversarial Suite

**Purpose:** prove core SaaS isolation.

Run:
1. `BOLA-001`
2. `BFLA-001`
3. `MASS-001`
4. `SUPABASE-RLS-001`
5. `TENANT-DEL-001`
6. `EXCESSDATA-001`, deeper field-level variant
7. `AUDIT-001`
8. New `CACHE-TENANT-001`
9. New `SEARCH-TENANT-001`
10. New `EXPORT-TENANT-001`
11. New `SUPPORT-IMPERSONATION-001`

**Gates:**
- This is the heart of SaaS security. Critical failures block release.
- Run only with seeded tenant A/B identities and known object fixtures.
- Tests must verify denial is indistinguishable where appropriate, especially `BOLA-001` and `PATTERN-002`.

---

## Stage 6 — Authn, Session, OAuth, and Token Abuse

**Purpose:** validate identity boundary after route map and auth modes are known.

Run:
1. `JWT-001`
2. `JWT-002`
3. `TOKEN-ROTATE-001`
4. `OAUTH-001`
5. `PWPOLICY-001`
6. `LOCK-001`
7. `ACCT-VERIFY-001`
8. `COOKIE-FLAGS-001`, live variant
9. `AUTH-STORAGE-001`
10. `TIMING-001`

**Ordering notes:**
- `JWT-001` before `JWT-002`; broken signature/claim validation invalidates token-purpose conclusions.
- `COOKIE-FLAGS-001` before CSRF decision finalization; CSRF posture depends on cookie/session transport.
- `LOCK-001` should run after password policy/register/reset surfaces are identified.
- `OAUTH-001` requires real redirect/callback route inventory.

---

## Stage 7 — Injection, Parser, SSRF, Webhook, and Business Logic Abuse

**Purpose:** attack dangerous inputs and async edges.

Run:
1. `INJ-001`
2. `XXE-001`
3. `SSTI-001`
4. `NOSQLI-001`
5. `SSRF-001`
6. `WEBHOOK-001`
7. `IDEM-001`
8. `RACE-001`
9. `RATE-001`
10. `HOSTHDR-001`
11. `CSRF-001`
12. `REDOS-001`, live timeout variant

**Ordering notes:**
- `SIZE-001` should already have passed before broader fuzzing.
- `WEBHOOK-001` before `IDEM-001`; if webhook signature verification is broken, idempotency is a second-order concern.
- `IDEM-001` before `RACE-001` for payment/webhook effects, because duplicate delivery and concurrent delivery often compose.
- `RATE-001` should run after identity model is known; otherwise it may test only IP throttling and miss account/API-key quotas.
- `SSRF-001` requires controlled callback infrastructure and egress allow/deny expectations.

---

## Stage 8 — LLM/AI Security

**Purpose:** validate model-mediated actions and data leakage.

Run:
1. `INV-006`
2. New `LLM-TOOL-INV-001`
3. `LLM-INJ-001`
4. `LLM-OUT-001`
5. `LLM-FAILOPEN-001`
6. New `LLM-TOOL-AUTHZ-001`
7. New `LLM-RAG-TENANT-001`
8. New `LLM-COST-001`
9. New `LLM-EVAL-REGRESSION-001`

**Ordering notes:**
- Prompt-injection checks are weak unless the tool/action graph is known.
- Output scrubbing must include retrieved context, tool results, logs, traces, and model output.
- Fail-open/kill-switch decisions should be tested after the guardrail path is known.

---

## Stage 9 — Decision, Triage, Evidence, and Release Gate

Run:
1. `DEC-001`
2. `DEC-002`
3. `CSRF-001`, if not finalized earlier
4. `TRIAGE-001`
5. `TEST-ISO-001`
6. `DOC-FRESH-001`
7. `DEPLOY-GATE-001`, final pre-release variant
8. New `SARIF-001`
9. New `REGRESSION-001`
10. New `SLA-001`

**Release rule:**
- No critical open.
- No high open without accepted risk and expiry.
- Every fail has owner/SLA.
- Every fixed critical/high gets a regression test.
- Evidence is reproducible from command/test output, not screenshots alone.

---

## 3. Right Tools & Software

## Secrets and Logging

Checks:
- `SEC-LEAK-001`
- `ENV-001`
- `ENV-002`
- `PATTERN-003`
- `FLOOR-A09`
- `ERRORLEAK-001`
- `LLM-OUT-001`

Tools:
- `gitleaks` — repo and git history secret scanning.
- `trufflehog` — verified secret discovery, historical scan.
- `detect-secrets` — baseline-based pre-commit secret scanning.
- `semgrep` — hardcoded fallback secrets, logging of secrets, unsafe error handling.
- `ripgrep` — fast custom pattern sweeps.
- `GitHub secret scanning` / `GitLab secret detection` — platform-native gate.
- `OWASP ZAP` — dynamic error leakage, stack traces, reflected secrets.
- `nuclei` — exposed files, debug pages, common misconfig templates.
- Custom planted-secret canary tests — inject fake token/password/PII and assert it does not appear in logs, error bodies, model output, or telemetry.

Recommended mapping:
- `SEC-LEAK-001`: `gitleaks detect --source . --no-git=false`, `trufflehog git file://...`
- `ENV-001`: `semgrep` + file glob checks.
- `ENV-002`: custom parser to reject non-empty values.
- `PATTERN-003`: `semgrep` rules for default secrets/JWT fallbacks.
- `FLOOR-A09`: `semgrep` + planted-secret log test.
- `ERRORLEAK-001`: `OWASP ZAP`, `nuclei`, custom HTTP probes.
- `LLM-OUT-001`: custom fake-secret eval suite plus model gateway trace scan.

---

## Dependencies, Supply Chain, and CI

Checks:
- `DEP-001`
- `DEP-002`
- `DEP-003`
- `CISEC-001`
- `FLOOR-A08`
- new `SBOM-001`
- new `SIGN-001`
- new `PROVENANCE-001`

Tools:
- `osv-scanner` — ecosystem vulnerability scan.
- `trivy fs` — dependencies, IaC, secrets, misconfig.
- `grype` — SBOM/container vulnerability scanning.
- `npm audit` / `pnpm audit` / `yarn npm audit` — Node.
- `pip-audit` / `safety` — Python.
- `govulncheck` — Go.
- `cargo audit` — Rust.
- `bundler-audit` — Ruby.
- `composer audit` / `symfony security:check` — PHP.
- `CodeQL` — deep SAST.
- `semgrep` — fast SAST and custom framework rules.
- `Snyk` or `Mend` — commercial SCA if desired.
- `Syft` — SBOM generation.
- `Cosign` / `Sigstore` — artifact signing.
- `SLSA GitHub Generator` — provenance.
- `Scorecard` — open-source dependency/repo posture.
- `zizmor` — GitHub Actions security linting.
- `pinact` — pin GitHub Actions to SHA.
- `StepSecurity Harden-Runner` — CI egress/runtime hardening.

Recommended mapping:
- `DEP-001`: `osv-scanner`, `trivy fs`, ecosystem-native audit.
- `DEP-002`: lockfile detector + package manager policy.
- `DEP-003`: `zizmor`, `pinact`, custom workflow parser.
- `CISEC-001`: verify presence and branch protection of `semgrep`, `CodeQL`, `gitleaks`, `osv-scanner`, `trivy`.
- `FLOOR-A08`: `semgrep`, `CodeQL`.

---

## Access Control and Multi-Tenancy

Checks:
- `INV-001`
- `INV-005`
- `APIINV-001`
- `AUTHN-REQUIRED-001`
- `AUTHZ-SERVER-001`
- `BOLA-001`
- `BFLA-001`
- `MASS-001`
- `SUPABASE-RLS-001`
- `EXCESSDATA-001`
- `TENANT-DEL-001`
- `PATTERN-002`
- `PATHTRAV-001`
- `REDIRECT-001`
- `WEBSOCKET-001`

Tools:
- `Schemathesis` — OpenAPI property-based API testing.
- `Dredd` — API contract testing.
- `OWASP ZAP` — authenticated active scan.
- `Burp Suite` — manual/automated authz testing.
- `Autorize` / `AuthMatrix` Burp extensions — authorization matrix testing.
- `Postman/Newman` — seeded identity test collections.
- `pytest` + `httpx` — Python adversarial tests.
- `Vitest/Jest` + `supertest` — Node route tests.
- `Playwright` — browser/session/localStorage/auth storage tests.
- `sqlfluff` / custom SQL probes — Supabase/Postgres RLS checks.
- `pgaudit` / Postgres introspection — policy presence and audit behavior.
- `semgrep` — missing auth decorators, client-side-only role checks, mass assignment antipatterns.

Recommended mapping:
- `BOLA-001`: custom two-identity fixtures, `pytest/httpx`, `supertest`, Burp `Autorize`.
- `BFLA-001`: role matrix generated from `INV-001`.
- `MASS-001`: schema-driven extra privileged fields using `Schemathesis`.
- `SUPABASE-RLS-001`: SQL introspection: `pg_class.relrowsecurity`, `pg_policies`, negative cross-user queries.
- `EXCESSDATA-001`: OpenAPI response schema diff + live response field allowlist.
- `WEBSOCKET-001`: `wscat`, `websocat`, custom WS client testing auth and Origin.
- `PATHTRAV-001`: `dotdotpwn`, `ffuf`, custom path traversal payloads.
- `REDIRECT-001`: custom URL payload corpus plus `nuclei` templates.

---

## Authn, Session, JWT, OAuth

Checks:
- `INV-002`
- `JWT-001`
- `JWT-002`
- `TOKEN-ROTATE-001`
- `COOKIE-FLAGS-001`
- `OAUTH-001`
- `PWPOLICY-001`
- `LOCK-001`
- `ACCT-VERIFY-001`
- `AUTH-STORAGE-001`
- `TIMING-001`

Tools:
- `jwt_tool` — JWT tampering/confusion tests.
- `jwt-cli` — token inspection.
- `jose` test harness — standards-compliant JWT generation.
- `oauth2-proxy` style callback probes or custom OAuth harness.
- `openid-client` conformance-inspired tests.
- `Playwright` — cookie flags, browser storage, OAuth flow.
- `OWASP ZAP` — session management passive/active checks.
- `HIBP k-anonymity API` or offline breach corpus — password breach checks.
- `semgrep` — JWT verification mistakes, cookie config, localStorage tokens.
- `hurl` / `curl` / `httpie` — scripted auth flow probes.

Recommended mapping:
- `JWT-001`: `jwt_tool` plus custom claim matrix.
- `JWT-002`: token inventory from `INV-002`; replay every non-access token against protected routes.
- `TOKEN-ROTATE-001`: custom refresh/logout replay tests.
- `OAUTH-001`: exact redirect URI, state, PKCE, nonce, scope tests with custom harness.
- `AUTH-STORAGE-001`: `Playwright` checks localStorage/sessionStorage/IndexedDB/cookies.
- `LOCK-001`: custom valid-shaped credential spray below/at/above threshold.
- `TIMING-001`: language-native constant-time checks plus statistical probe only for token/secret compare paths.

---

## Injection and Input Handling

Checks:
- `INJ-001`
- `FLOOR-A03`
- `XXE-001`
- `SSTI-001`
- `NOSQLI-001`
- `REDOS-001`
- `SIZE-001`
- `FLOOR-A08`
- `PAGINATION-001`
- `HOSTHDR-001`

Tools:
- `semgrep` — unsafe query construction, command execution, template rendering, deserialization.
- `CodeQL` — taint analysis.
- `sqlmap` — SQL injection against authorized staging only.
- `NoSQLMap` — NoSQL injection.
- `tplmap` — SSTI.
- `dalfox` — XSS.
- `XSStrike` — XSS.
- `commix` — command injection.
- `defusedxml` checks / `xxeinjector` where safe — XXE.
- `rxxr2` / `safe-regex` / `redos-detector` — ReDoS.
- `Schemathesis` — schema-driven fuzzing.
- `Hypothesis` / `fast-check` — property-based input tests.
- `ffuf` — parameter discovery and traversal payloads.

Recommended mapping:
- `FLOOR-A03`: `semgrep`, `CodeQL`, ORM-specific rules.
- `INJ-001`: `Schemathesis` + targeted `sqlmap`, `dalfox`, `commix`.
- `XXE-001`: parser config static rules plus safe local XML probe.
- `SSTI-001`: `tplmap` plus route-specific templates.
- `NOSQLI-001`: `NoSQLMap`, custom `$ne`, `$gt`, `$regex` payloads.
- `REDOS-001`: static regex analysis plus live timeout budget tests.
- `SIZE-001`: body size/depth/decompression bomb harness.
- `HOSTHDR-001`: `nuclei`, custom Host/XFH probes.

---

## Headers, CORS, CSRF, Browser Exposure

Checks:
- `HDR-001`
- `HDR-002`
- `CLICKJACK-001`
- `CSRF-001`
- `COOKIE-FLAGS-001`
- `CLIENT-ENV-001`
- `AUTH-STORAGE-001`
- `SOURCEMAP-001`

Tools:
- `OWASP ZAP` — passive scan and browser-relevant checks.
- `nuclei` — HTTP misconfiguration templates.
- `Mozilla Observatory` style checks, self-hosted if possible.
- `securityheaders.com` style checks, but avoid leaking internal preview URLs to third-party SaaS unless approved.
- `Playwright` — browser storage, CORS behavior, clickjacking frame tests.
- `curl` / `httpx` — header matrix.
- `semgrep` — CORS wildcard with credentials, cookie config, client env prefixes.
- `source-map-explorer` / build artifact inspection — source map exposure.

Recommended mapping:
- `HDR-001`: `nuclei`, `ZAP`, custom header assertions.
- `HDR-002`: Origin reflection matrix with credentials.
- `CLICKJACK-001`: header check plus iframe embedding proof.
- `CSRF-001`: transport-aware custom test; cookie-auth mutation without CSRF token must fail.
- `SOURCEMAP-001`: direct HTTP requests for `*.map`, build manifest checks.

---

## Rate Abuse, Race, Idempotency, and Business Logic

Checks:
- `PATTERN-001`
- `RATE-001`
- `LOCK-001`
- `RACE-001`
- `IDEM-001`
- `PAGINATION-001`

Tools:
- `k6` — controlled load/concurrency.
- `vegeta` — rate/concurrency probes.
- `hey` / `wrk` — simple load probes.
- `Locust` — stateful user flows.
- `pytest-xdist` / async test harness — concurrent quota/payment operations.
- `toxiproxy` — retry/timeout simulation.
- `mitmproxy` — replay/idempotency tests.
- `semgrep` — check-then-act patterns, naive IP limiter.

Recommended mapping:
- `RATE-001`: identity/IP/API-key rotating request harness.
- `LOCK-001`: custom login failure threshold test.
- `RACE-001`: `k6` or async custom test against seeded quota/balance.
- `IDEM-001`: duplicate idempotency-key and retry storm test.
- `PAGINATION-001`: max page size and unbounded query probes.

---

## SSRF, Webhooks, and Outbound Calls

Checks:
- `INV-003`
- `SSRF-001`
- `WEBHOOK-001`
- `IDEM-001`
- `TIMING-001`

Tools:
- `interactsh` — OOB SSRF/DNS/HTTP callback detection.
- `Burp Collaborator` — OOB detection.
- `ssrfmap` — SSRF payload automation.
- `nuclei` — SSRF templates.
- `toxiproxy` — redirect/rebinding/timeouts.
- Custom DNS rebinding harness.
- `stripe trigger` / provider CLIs — webhook replay in staging.
- `openssl` / HMAC scripts — raw-body signature tests.
- `mitmproxy` — webhook replay/mutation.

Recommended mapping:
- `SSRF-001`: custom URL allowlist/blocklist tests, redirect validation, resolved-IP validation, DNS rebinding simulation.
- `WEBHOOK-001`: provider-specific raw-body HMAC fixtures, timestamp replay, duplicate delivery.
- `TIMING-001`: code inspection for constant-time compare plus focused measurement.

---

## LLM/AI

Checks:
- `INV-006`
- `LLM-INJ-001`
- `LLM-OUT-001`
- `LLM-FAILOPEN-001`

Tools:
- `garak` — LLM vulnerability scanning.
- `promptfoo` — prompt regression/eval suite.
- `Giskard` — LLM testing.
- `PyRIT` — adversarial AI testing.
- `OpenAI Evals`-style harness or custom eval runner.
- `langfuse` / `Helicone` / gateway traces — model call observability.
- `Presidio` — PII detection.
- `detect-secrets`/custom regex — secret output detection.
- `semgrep` — unsafe tool invocation, prompt concatenation of secrets.
- Custom fake-tool sandbox — prove prompt injection cannot trigger unauthorized tool calls.

Recommended mapping:
- `LLM-INJ-001`: `promptfoo`, `garak`, `PyRIT`, domain-specific payloads.
- `LLM-OUT-001`: planted secrets and PII in retrieved context; assert not emitted.
- `LLM-FAILOPEN-001`: kill-switch/fail-open chaos test.
- New `LLM-TOOL-AUTHZ-001`: fake malicious prompt attempts tool call across tenant/admin boundary.
- New `LLM-RAG-TENANT-001`: tenant A asks for tenant B documents through RAG.

---

## Deploy, Ops, Runtime, and Cloud

Checks:
- `INV-007`
- `DEPLOY-GATE-001`
- `DEC-001`
- `DEC-002`
- `FLOOR-A02`
- `FLOOR-A05`
- `TEST-ISO-001`
- `DOC-FRESH-001`
- `TRIAGE-001`

Tools:
- `checkov` — IaC and cloud config.
- `tfsec` / `trivy config` — Terraform/IaC.
- `kics` — IaC scan.
- `kube-score`, `kube-linter`, `kubescape`, `polaris` — Kubernetes posture.
- `prowler` — AWS security benchmark.
- `ScoutSuite` — cloud account audit.
- `Cloudsplaining` — AWS IAM privilege analysis.
- `IAM Access Analyzer` — AWS IAM findings.
- `Snyk IaC` — commercial option.
- `Open Policy Agent` / `conftest` — policy-as-code.
- `Falco` — runtime detection if applicable.
- `Wiz`, `Lacework`, `Orca`, `Prisma Cloud` — commercial CNAPP integrations.

Recommended mapping:
- `FLOOR-A05`: `nuclei`, `ZAP`, `checkov`, runtime env probes.
- `FLOOR-A02`: TLS scanner, HSTS check, cookie secure flags, hash config inspection.
- `DEC-001`/`DEC-002`: config and runbook evidence checks.
- `DEPLOY-GATE-001`: deployment metadata, rollback command, smoke test command.
- `TEST-ISO-001`: run full security test suite in randomized order and clean environment.

---

## 4. Right Environments

## Pre-Commit

Run very fast, local, no network unless configured:
- `SEC-LEAK-001`
- `ENV-001`
- `ENV-002`
- `PATTERN-003`
- `DEP-002`
- `REDOS-001`, static only
- `CLIENT-ENV-001`, static only
- `PATTERN-004`
- `FLOOR-A08`
- `FLOOR-A03`, lightweight Semgrep rules

Why:
- Prevent secrets, obvious dangerous patterns, and lockfile mistakes before they enter history.
- Keep under ~30 seconds.
- Should use `pre-commit`, `husky`, `lint-staged`, or equivalent.

---

## CI Pull Request

Run deterministic static and unit-level security tests:
- `SEC-LEAK-001`
- `DEP-001`
- `DEP-002`
- `DEP-003`
- `CISEC-001`
- `PATTERN-001`
- `PATTERN-002`
- `PATTERN-003`
- `PATTERN-004`
- `FLOOR-A03`
- `FLOOR-A08`
- `FLOOR-A09`
- `COOKIE-FLAGS-001`, static config
- `CLIENT-ENV-001`
- `TEST-ISO-001`
- `DOC-FRESH-001`

Why:
- Blocks bad code before preview deploy.
- Can annotate PRs with SARIF.
- Does not require seeded environments.

---

## CI Build Artifact / Container

Run after build:
- `DEP-001`, artifact/image variant
- `SOURCEMAP-001`, artifact check
- `CLIENT-ENV-001`, built JS scan
- `FLOOR-A05`, config artifact check
- new `CONTAINER-001`
- new `CONTAINER-002`
- new `SBOM-001`
- new `SIGN-001`
- new `IAC-001`

Why:
- Source can look clean while built output leaks env vars, source maps, vulnerable OS packages, or debug config.

---

## Ephemeral Preview

Run safe dynamic tests:
- `HDR-001`
- `HDR-002`
- `CLICKJACK-001`
- `COOKIE-FLAGS-001`
- `SOURCEMAP-001`
- `AUTH-STORAGE-001`
- `AUTHN-REQUIRED-001`
- `AUTHZ-SERVER-001`
- `EXCESSDATA-001`
- `PATHTRAV-001`
- `REDIRECT-001`
- `WEBSOCKET-001`
- `ERRORLEAK-001`
- `SIZE-001`
- `PAGINATION-001`
- `CSRF-001`

Why:
- Live headers/cookies/CORS/browser behavior require a running app.
- Preview is disposable and isolated.

---

## Staging

Run seeded adversarial and heavier tests:
- `BOLA-001`
- `BFLA-001`
- `MASS-001`
- `SUPABASE-RLS-001`
- `TENANT-DEL-001`
- `JWT-001`
- `JWT-002`
- `TOKEN-ROTATE-001`
- `OAUTH-001`
- `PWPOLICY-001`
- `LOCK-001`
- `RATE-001`
- `RACE-001`
- `IDEM-001`
- `SSRF-001`
- `WEBHOOK-001`
- `INJ-001`
- `XXE-001`
- `SSTI-001`
- `NOSQLI-001`
- `HOSTHDR-001`
- `LLM-INJ-001`
- `LLM-OUT-001`
- `LLM-FAILOPEN-001`

Why:
- Needs realistic auth, tenants, data, webhooks, queues, and model/tool behavior.
- Should use fake payment/email/SMS/model providers or sandbox accounts.

---

## Container Runtime / Kubernetes / Cloud

Run:
- new `CONTAINER-001`
- new `CONTAINER-002`
- new `K8S-001`
- new `IAC-001`
- new `IAM-001`
- new `STORAGE-001`
- `FLOOR-A05`
- `FLOOR-A02`
- `DEPLOY-GATE-001`

Why:
- SaaS compromise often happens through cloud/IAM/storage/metadata, not just route handlers.

---

## Prod Readonly

Run only passive or explicitly safe checks:
- `HDR-001`
- `HDR-002`
- `CLICKJACK-001`
- `SOURCEMAP-001`
- `COOKIE-FLAGS-001`
- `FLOOR-A02`
- `FLOOR-A05`, non-invasive probes
- `ERRORLEAK-001`, safe known error route only
- `APIINV-001`, passive route inventory from gateway/logs/specs
- `AUDIT-001`, readonly config/log sink verification
- new `DMARC-001`
- new `DNS-001`
- new `CERT-001`
- new `BACKUP-RESTORE-001`, evidence-only unless test environment

Why:
- Prod scanning must not mutate data, trigger lockouts, send emails, exhaust quotas, create billing events, or call paid LLMs at scale.

---

## 5. Missing Checks or Capabilities for Real SaaS

## Cloud, IaC, and Runtime

### `IAC-001` — Infrastructure-as-code has no critical misconfig
Oracle:
- `checkov`/`tfsec`/`trivy config` find no critical/high issues in Terraform, CloudFormation, Kubernetes, Helm, Docker Compose.
- Public network exposure, weak security groups, public DBs, unencrypted storage, and permissive IAM fail.

### `IAM-001` — Cloud IAM least privilege
Oracle:
- No wildcard admin policies on app/CI roles.
- CI deploy role cannot read all secrets unless required.
- Runtime role cannot mutate infrastructure.
- `Cloudsplaining`, `Prowler`, or cloud-native analyzer has no critical findings.

### `STORAGE-001` — Object storage tenant isolation and privacy
Oracle:
- Buckets are private by default.
- Signed URLs expire and are scoped to object/tenant.
- Tenant A cannot read/write/list tenant B objects.
- Public bucket policy is absent unless explicitly documented.

### `K8S-001` — Kubernetes workload hardening
Oracle:
- No privileged pods.
- No hostPath unless approved.
- Non-root containers.
- Resource limits set.
- Network policies exist for sensitive services.
- Secrets not mounted broadly.

### `CONTAINER-001` — Container image has no critical exploitable CVEs
Oracle:
- `trivy image` or `grype` reports no critical/high runtime-relevant vulnerabilities above policy threshold.

### `CONTAINER-002` — Container runtime hardening
Oracle:
- Non-root user.
- Minimal capabilities.
- Read-only root filesystem where practical.
- No embedded secrets in layers.

---

## Data Protection and Privacy

### `PII-INV-001` — PII/data classification inventory
Oracle:
- Every datastore/table/collection has data classification.
- Fields are labeled: public, internal, tenant confidential, PII, secret, regulated.
- Access-control and logging checks consume these labels.

### `RETENTION-001` — Retention and deletion policy enforced
Oracle:
- User/tenant deletion removes or anonymizes expected records.
- Exceptions are documented for audit/legal retention.
- Backups have retention limits.

### `EXPORT-001` — Data export is scoped and audited
Oracle:
- User/tenant export includes only owned data.
- Export requires auth/re-auth for sensitive data.
- Export action is logged.
- Generated files expire.

### `BACKUP-RESTORE-001` — Backups are encrypted and restorable
Oracle:
- Backups are encrypted.
- Access is restricted.
- Restore test has recent evidence.
- Backup does not break tenant deletion guarantees beyond documented retention.

### `ANALYTICS-PII-001` — Analytics/telemetry does not leak sensitive data
Oracle:
- No secrets, tokens, passwords, or high-risk PII sent to analytics/session replay/error tools.
- Planted secret is absent from Sentry/Datadog/PostHog/Segment/etc.

---

## Admin Plane and Support Operations

### `ADMIN-001` — Admin routes require strong auth and explicit role
Oracle:
- Admin endpoints require admin role server-side.
- Normal user token fails.
- Support user role cannot access owner-only controls.

### `SUPPORT-IMPERSONATION-001` — Support impersonation is controlled
Oracle:
- Impersonation requires elevated role, reason, duration, audit log.
- Impersonated session is visibly marked.
- Dangerous actions are blocked or require step-up.
- Tenant boundary still applies.

### `MFA-001` — MFA enforced for privileged/admin users
Oracle:
- Admin/support/billing-owner accounts require MFA or SSO policy.
- Sensitive actions require step-up where applicable.

### `RBAC-MATRIX-001` — Authorization matrix is complete
Oracle:
- Every route maps to allowed roles/scopes.
- Tests generated from matrix pass.
- Unknown routes fail closed.

---

## Billing, Payments, and Quotas

### `BILLING-WEBHOOK-001` — Provider webhook state transitions are safe
Oracle:
- Stripe/Paddle/LemonSqueezy/etc. webhook signature verified.
- Out-of-order events do not grant incorrect entitlement.
- Duplicate events are idempotent.
- Downgrade/cancel/refund paths update access correctly.

### `ENTITLEMENT-001` — Paid feature access cannot be forged
Oracle:
- Client-side plan flags are ignored.
- Server checks entitlement from trusted source.
- Tenant A cannot use tenant B subscription.

### `TRIAL-ABUSE-001` — Trial/free-tier abuse controls
Oracle:
- Signup, invite, coupon, trial, and usage-grant paths have abuse controls.
- Rotating email/IP/device does not trivially bypass all limits.

---

## Queues, Jobs, and Async Processing

### `QUEUE-AUTHZ-001` — Background jobs preserve tenant/auth context
Oracle:
- Job payload includes trusted tenant/user context.
- Worker revalidates authorization where needed.
- Tenant A job cannot process tenant B resource.

### `QUEUE-IDEM-001` — Async jobs are idempotent
Oracle:
- Retried job applies side effects once.
- Duplicate message delivery is safe.
- Poison messages are quarantined.

### `EMAIL-SMS-001` — Messaging abuse and leakage
Oracle:
- Email/SMS endpoints are rate-limited.
- Reset/invite/verification links have expiry and single-use semantics.
- Messages do not leak secrets or tenant data.

---

## Cache, Search, and Derived Data

### `CACHE-TENANT-001` — Cache keys are tenant-scoped
Oracle:
- Cache keys include tenant/user/scope where necessary.
- Tenant A cannot receive cached tenant B response.
- Purge/invalidation respects tenant boundaries.

### `SEARCH-TENANT-001` — Search indexes enforce tenant isolation
Oracle:
- Search queries include tenant filter server-side.
- Index documents carry tenant ID.
- Tenant A cannot retrieve tenant B documents via search/autocomplete.

### `RAG-TENANT-001` — RAG retrieval is tenant-scoped
Oracle:
- Vector search filters by tenant/user permissions.
- Prompt injection cannot remove tenant filter.
- Retrieved snippets from tenant B never appear for tenant A.

---

## DNS, Email, Domains, and TLS

### `DNS-001` — DNS takeover and dangling records
Oracle:
- No dangling CNAMEs to unclaimed services.
- No stale preview/custom domain records.
- Subdomain takeover tools return clean.

Tools:
- `subjack`, `subzy`, `tko-subs`, `dnsx`.

### `DMARC-001` — Email authentication configured
Oracle:
- SPF, DKIM, and DMARC exist.
- DMARC policy is at least quarantine/reject for production domains where feasible.

Tools:
- `checkdmarc`.

### `CERT-001` — TLS certificate and HSTS posture
Oracle:
- Valid cert chain.
- No weak TLS versions/ciphers.
- HSTS set for production app domains.

Tools:
- `testssl.sh`, `sslyze`.

---

## Observability, Incident Response, and Governance

### `ALERT-001` — Security-relevant events produce alerts
Oracle:
- Login spray, admin action, webhook verification failure, SSRF block, WAF block, and privilege change create observable events.
- Alerts have owners and routes.

### `RUNBOOK-001` — Critical controls have incident runbooks
Oracle:
- Secret leak, account takeover, tenant data exposure, webhook abuse, and LLM leakage have runbooks.
- Runbooks include disable/kill-switch and rollback.

### `KEY-ROTATE-001` — Secret/key rotation works
Oracle:
- JWT signing keys, webhook secrets, API keys, DB creds, and OAuth secrets have documented rotation.
- Rotation test succeeds without downtime where required.

### `AUDIT-EXPORT-001` — Audit evidence is exportable
Oracle:
- Findings, proofs, decisions, suppressions, and risk acceptances export to markdown/JSON/SARIF.
- Evidence includes command, environment, timestamp, target, and artifact hash.

---

## Product Capabilities Missing

### Capability 1 — Dependency graph and planner
The registry should support:
```yaml
requires:
  - INV-001
  - INV-005
unlocks:
  - BOLA-001
blocks_if_fail: true
safe_environments:
  - ephemeral-preview
  - staging
unsafe_environments:
  - prod
```

### Capability 2 — Tool adapter layer
Each check should have:
```yaml
tools:
  - name: semgrep
    command: semgrep --config p/security-audit
    evidence: sarif
  - name: custom
    template: python-fastapi/test_bola.py
```

### Capability 3 — Evidence schema
Every result should include:
```yaml
check_id:
status:
environment:
target:
tool:
command:
started_at:
ended_at:
evidence_files:
observed:
expected:
negative_control:
risk:
owner:
expiry:
```

### Capability 4 — Asset model
Inventories should produce reusable assets:
- routes;
- roles;
- token types;
- data stores;
- tenants;
- object types;
- external calls;
- queues;
- model tools;
- secrets;
- deployments.

Every adversarial test should consume this model instead of hardcoded guesses.

### Capability 5 — Safe test data generator
The tool needs seeded fixtures:
- tenant A/B;
- user/admin/support;
- objects per tenant;
- billing subscription;
- quota counter;
- webhook event;
- LLM document corpus;
- object storage files.

Without fixtures, adversarial proof will be shallow or manual.

---

## 6. Top 10 Prioritized Recommendations

### 1. Turn the registry into a dependency-aware execution DAG
Add `requires`, `unlocks`, `blocks_if_fail`, `environment`, `safe_in_prod`, `destructive`, `needs_seed_data`, `tool_adapter`, and `evidence_schema` to every check.

This is the biggest leap from “list” to “programme”.

---

### 2. Split the current `phase` model into real stages
Replace broad phases with ordered stages:

1. `scope-safety`
2. `inventory`
3. `local-static`
4. `ci-static`
5. `artifact-container-iac`
6. `preview-dynamic`
7. `staging-adversarial`
8. `prod-readonly`
9. `decision-triage-release`

Then map every check to one or more stages.

---

### 3. Add concrete tool adapters for every static and dynamic domain
Minimum first-class tool set:
- `gitleaks`
- `trufflehog`
- `semgrep`
- `CodeQL`
- `osv-scanner`
- `trivy`
- `grype`
- `syft`
- `checkov`
- `tfsec` or `trivy config`
- `zizmor`
- `nuclei`
- `OWASP ZAP`
- `Schemathesis`
- `sqlmap`
- `jwt_tool`
- `Playwright`
- `k6`
- `interactsh`
- `promptfoo`
- `garak`

The runner should detect missing tools and produce install commands or degraded-mode warnings.

---

### 4. Build an asset inventory model that powers tests
`INV-001` through `INV-008` should not just write prose. They should produce `.bedrock/assets.json`.

Example objects:
- `routes[]`
- `auth_modes[]`
- `roles[]`
- `token_types[]`
- `tenant_resources[]`
- `external_fetches[]`
- `webhooks[]`
- `llm_surfaces[]`
- `datastores[]`
- `secrets[]`
- `deploy_targets[]`

Adversarial templates should consume this model.

---

### 5. Add seeded SaaS fixture generation
The tool should create or request:
- tenant A and tenant B;
- user A, user B, admin, support;
- object A and object B;
- billing entitlement;
- quota/balance counter;
- webhook secret and sample event;
- storage object per tenant;
- RAG document per tenant.

Without this, `BOLA-001`, `BFLA-001`, `RACE-001`, `SUPABASE-RLS-001`, `LLM-RAG-TENANT-001`, and `ENTITLEMENT-001` cannot be consistently proven.

---

### 6. Expand beyond appsec into cloud, data, CI, runtime, and admin plane
Add the missing checks:
- `IAC-001`
- `IAM-001`
- `STORAGE-001`
- `CONTAINER-001`
- `CONTAINER-002`
- `K8S-001`
- `PII-INV-001`
- `BACKUP-RESTORE-001`
- `ADMIN-001`
- `SUPPORT-IMPERSONATION-001`
- `MFA-001`
- `BILLING-WEBHOOK-001`
- `ENTITLEMENT-001`
- `CACHE-TENANT-001`
- `SEARCH-TENANT-001`
- `QUEUE-AUTHZ-001`
- `DMARC-001`
- `DNS-001`
- `KEY-ROTATE-001`
- `ALERT-001`

These are required for “ultimate SaaS”, not optional extras.

---

### 7. Make every oracle executable, not just standards-linked
Keep OWASP/CWE/RFC references, but add explicit pass/fail logic.

Example for `BOLA-001`:
- Given tenant A object ID and tenant B token.
- When tenant B requests tenant A object.
- Then response status/body/error shape matches nonexistent object.
- And no audit/log secret leak occurs.
- And tenant A object remains unchanged.
- Negative control: tenant A token can access tenant A object.

This style should be universal.

---

### 8. Introduce evidence, triage, suppression, and regression lifecycle
Add:
- SARIF export.
- JSON evidence ledger.
- finding deduplication.
- suppression with expiry and owner.
- risk acceptance with expiry.
- severity SLA.
- generated regression test per fixed high/critical.
- GitHub/Jira/Linear issue export.
- CI annotations.

`TRIAGE-001` should become a lifecycle subsystem, not a single decision check.

---

### 9. Create environment-specific safety rails
Every check should be marked:
- `readonly`
- `mutating`
- `destructive`
- `load_generating`
- `cost_generating`
- `external_side_effect`
- `prod_allowed`
- `requires_sandbox_provider`

Examples:
- `RACE-001`: staging only, mutating, concurrency capped.
- `RATE-001`: staging/pre-prod, load-generating.
- `LLM-INJ-001`: cost-generating; model gateway sandbox preferred.
- `WEBHOOK-001`: staging with provider test mode.
- `SOURCEMAP-001`: prod-readonly safe.
- `HDR-001`: prod-readonly safe.

This prevents the tool from becoming dangerous.

---

### 10. Reframe the UI around “security programme progress,” not 76 rows
The console should show:
- Stage progress.
- Blockers.
- Dependency graph.
- Environment readiness.
- Tool readiness.
- Critical path to release.
- Evidence quality.
- Open risk by owner/SLA.
- “Run next safest useful action.”
- “Generate missing fixture.”
- “Install missing tool.”
- “Promote proof to regression.”

The ultimate UX is not “here are 76 checks.” It is “here is the exact next action that moves this SaaS closer to releasable security.”

---

# Bottom Line

`bedrock-security` already has the right philosophical core: adversarial proof, second-order SaaS checks, and a ledger that refuses hand-wavy security claims.

The biggest elevation is not adding 200 more checks. The biggest elevation is turning the 76 checks into an environment-aware, dependency-aware, tool-backed, evidence-producing SaaS security operating system.

The north star should be:

> Inventory creates assets. Assets generate tests. Tests run only in safe environments. Tools produce evidence. Evidence drives gates. Gates create regressions. Regressions protect every release.
