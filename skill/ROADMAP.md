# bedrock-security — Elevation Roadmap (the path to the ultimate SaaS security tool)

> Produced by a deliberate multi-LLM process, not one pass:
> **Sequential council** (each built on the last) → **GPT** (codex, breadth + depth) →
> **Gemini** (pragmatic pruning, serverless realities) → **Claude** (synthesis).
> Then a **Sonnet squad** (3 agents, one per section) detailed it into a buildable spec.
> Full source analysis is in `_intake/council/` (`01-gpt`, `02-gemini`, `03-synthesis`,
> `S1-checks-ordering`, `S2-tools-environments`, `S3-flow-format-proof` — ~230KB).

---

## 0. The verdict — what "ultimate" means here

**Depth-on-demand.** The ceiling is enterprise-grade, but it stays **dormant and free**
until a target's *actual surface* triggers it. Every powerful capability (asset model,
evidence schema, environment rails, tenant/billing/LLM checks) is built into the engine +
registry schema; nothing runs, costs, or nags unless the project's assets prove it applies.
**Comprehensive where a real SaaS bleeds; ruthless everywhere else.** We add the ~15 checks a
Vercel/Supabase/Stripe SaaS actually dies from, and reject the CNAPP/K8s/Jira zoo no
small team will ever run. The north star:

> Inventory creates assets → assets generate tests → tests run only in safe environments →
> tools produce evidence → evidence drives gates → gates create regressions → regressions
> protect every release.

The single biggest leap is **from a flat 76-check LIST → a dependency-aware, environment-aware,
tool-backed, evidence-producing security OPERATING SYSTEM.** Not 200 more checks.

---

## 1. The 7-stage model (the right order)

GPT proposed 9 stages, Gemini 5; the synthesis is **7** — with the key insight that
**environment is an orthogonal `environments[]` TAG, not a stage** (that conflation is what
made the 5-vs-9 fight). Stages are the logical pipeline; the same check can run in several
environments.

| Stage | Name | Purpose | Representative checks |
|---|---|---|---|
| **0** | SCOPE & SAFETY | hard gate — authority, target, blast-radius | `INV-007`, `DEPLOY-GATE-001`, **`SCOPE-001`**, **`DATA-SAFETY-001`** |
| **1** | FRAME | enumerate → emit `assets.json` | `INV-008→001→APIINV-001→005→002→003→004→006` (serial) |
| **2** | STATIC | cheap local/CI fail-fast | `SEC-LEAK-001`, `ENV-*`, `PATTERN-*`, `DEP-*`, `FLOOR-*`, `CLIENT-ENV-001`, `REDOS-001`, **`SBA-ANON-001`**, **`NEXT-RSC-001`** |
| **3** | DYNAMIC-PASSIVE | running app, non-destructive | `HDR-*`, `CLICKJACK-001`, `AUTHN-REQUIRED-001`, `SIZE-001`, `PAGINATION-001`, `ERRORLEAK-001`, **`EDGE-MW-001`**, **`DMARC/CERT/DNS-001`** |
| **4** | DYNAMIC-ADVERSARIAL | seeded identities, the SaaS core | `BOLA/BFLA/MASS`, `SUPABASE-RLS`, `JWT-*`, `OAUTH/LOCK/RACE/RATE`, `SSRF/WEBHOOK/INJ/XXE/SSTI`, **`BILLING-WEBHOOK`**, **`ENTITLEMENT`**, **`CACHE-TENANT`**, **`ADMIN`**, **`ANALYTICS-PII`** |
| **5** | LLM / AI | isolated (only cost-generating family) | `LLM-INJ/OUT/FAILOPEN`, **`LLM-BLIND-001`**, **`RAG-TENANT-001`** |
| **6** | DECISION / TRIAGE / VERDICT | gate the release | `CSRF-001`, `DEC-*`, `TRIAGE-001`, `TEST-ISO-001`, `DOC-FRESH-001`, `DEPLOY-GATE-001` (lock) |

### Top intra-stage ordering rules (dependencies that matter)
1. **`SCOPE-001` / `DEPLOY-GATE-001` block ALL live stages** — no HTTP probe fires without them.
2. **`AUTHN-REQUIRED-001` → `BOLA-001`** — if anonymous users read the data, object-authz is moot.
3. **`JWT-001` → `JWT-002`** (`blocks_if_fail`) — a broken signature validator invalidates purpose-confusion conclusions.
4. **`WEBHOOK-001` → `IDEM-001` → `RACE-001`** — verify signature before dup-delivery before concurrency.
5. **`SIZE-001` (St.3) → all fuzzing (St.4)** — prevents accidental DoS during the injection suite.
6. **`INV-001`/`INV-002` must PASS** before any route-/token-dependent check (10+ are BLOCKED otherwise).
7. **`INV-008` (stack detect) runs first** — template selection + RSC/Edge/IaC applicability depend on it.
8. **Empty `assets.llm_surfaces[]` → all of Stage 5 resolves N/A instantly** (the "lighter than air" guarantee).
9. **`CSRF-001` waits for Stage 6** — its posture depends on the cookie/auth transport confirmed in St.4.

---

## 2. The DAG — new registry schema (4 keys, fully back-compat)

```yaml
# added to each check in registry.yaml; missing keys default to "no dep / all env / readonly"
requires:       [INV-001, INV-005]   # BLOCKED until these PASS / produce their assets
provides:       [routes, roles]      # asset keys this check writes (Stage-1 FRAME only)
blocks_if_fail: true                 # on FAIL, propagate BLOCKED to everything that requires me
environments:   [staging]            # where this may run (safety tag; enforced by --env)
safety:                              # 6 booleans; default = safe profile
  destructive: false
  cost_generating: false
  needs_seed_data: false
  readonly: true
  safe_in_prod: true
  external_side_effect: false
```
Resolution: stdlib **`graphlib.TopologicalSorter`** in the runner. A FAIL with `blocks_if_fail`
marks downstream `BLOCKED` (saves time + noise). Back-compat is total: the existing 76 checks
keep running unchanged because absent keys default to no-dep/all-env/readonly.

---

## 3. The additions — IN / DEFER / REJECT (decisive)

**~15 IN (build now — the real SaaS bleed-points):**
`SCOPE-001`, `DATA-SAFETY-001` (safety gates) · `SBA-ANON-001` (Supabase anon key + no RLS =
instant full-DB compromise) · `NEXT-RSC-001` (RSC leaking DB objects into client) · `EDGE-MW-001`
(Next middleware auth bypass) · `LLM-BLIND-001` (SSRF via LLM fetch-tool) · `RAG-TENANT-001`,
`CACHE-TENANT-001`, `SEARCH-TENANT-001` (cross-tenant via derived data) · `BILLING-WEBHOOK-001`,
`ENTITLEMENT-001` (forge paid access) · `ADMIN-001` (folds into BFLA) · `ANALYTICS-PII-001`
(secrets/PII to PostHog/Sentry) · `DMARC-001`, `CERT-001`, `DNS-001` (email/TLS/subdomain-takeover)
· + a JSON **evidence ledger** and **proof→regression** promotion.

**~12 DEFER (schema-ready, dormant, zero cost if absent):** `EXPORT-TENANT`, `SUPPORT-IMPERSONATION`,
`TRIAL-ABUSE`, `MFA`, `QUEUE-AUTHZ/IDEM`, `EMAIL-SMS`, `IAC` (opt-in), `STORAGE` (narrowed to
Supabase Storage RLS), `PII-INV`, `RETENTION`, `BACKUP-RESTORE`, `KEY-ROTATE`, `ALERT/RUNBOOK`.

**~10 REJECT (CNAPP / bureaucracy — bloat for a small SaaS):** `IAM-001`, `CONTAINER-001/002`,
`K8S-001`, `SBOM/SIGN/PROVENANCE/LICENSE/Scorecard`, `RBAC-MATRIX` (dup of BFLA), and the
suppression-SLA-Jira/Linear/SARIF lifecycle. **The RED ledger is the SLA.**

---

## 4. Tools & environments

**4-tool mandatory core** (everything else is an optional adapter):
1. **`semgrep`** — SAST + antipatterns + custom rules (RSC leak, anon-key, edge-MW, cookie flags, ReDoS, unsafe deser, hardcoded secrets, JWT bugs)
2. **`nuclei`** — dynamic HTTP probes (headers, CORS, SSRF templates, source maps, error leakage, TLS)
3. **project test runner** (pytest+httpx / vitest+supertest) — all Stage-4/5 adversarial proofs
4. **native audit + `gitleaks`** (`npm audit`/`pip-audit`/`osv-scanner` + `gitleaks detect`)

**Graceful degradation** — every tool-backed check has a `strategy[]` ladder the runner walks
top-down: **ideal tool → fallback tool → baseline grep → `NEEDS-PROOF` (never silent)**. A missing
tool never aborts the run; it degrades and the console offers the install command.

**`--env` enforcement matrix:** `pre-commit | ci | preview | staging | prod`. The runner refuses a
check whose `safety` profile is incompatible (e.g. adversarial/destructive checks only on
`staging`; `prod` allows only `readonly:true, safe_in_prod:true`; the LLM stage additionally needs
explicit `--stages=llm` because it's `cost_generating`). Incompatible → `BLOCKED(env)` in the ledger.

**Explicitly NOT in the core** (optional adapters or permanent rejects): ZAP, Burp, sqlmap, garak,
Wiz/Snyk/CNAPP, the K8s toolchain, the SBOM/sign chain, Jira/ticket sync.

---

## 5. Data, flow & UX

- **`.bedrock/assets.json`** (emitted by Stage-1 FRAME, consumed by every adversarial template —
  no more hardcoded placeholders): `routes` · `roles` · `token_types` · `tenant_resources` ·
  `external_fetches` · `webhooks` · `llm_surfaces` · `datastores` · `secrets` (names only) ·
  `deploy_targets`. Each carries the fields the matching checks need (e.g. `token_types` drives
  JWT-002; `tenant_resources` drives BOLA/RLS/TENANT-DEL; empty `llm_surfaces` ⇒ Stage 5 = N/A).
- **Fixture seeding contract:** a rollback-wrapped `seed_bedrock.sql` (tenant A/B + dummy rows) and
  a Stripe-CLI fixture, so BOLA/RACE/RLS/WEBHOOK run automatically instead of by hand.
- **Enriched `ledger.json` evidence schema** (per check): `status` (+ `BLOCKED` + `blocked_reason`),
  `environment`, `target`, `tool` (strategy winner), `command` (reproducible), `started/ended`,
  `observed`, `expected`, `negative_control`, `evidence_files`, `triage_class`, `risk/owner/expiry`
  (suppression with mandatory expiry), `regression_test_path`, `oracle`, `confidence`. No SARIF/Jira.
- **Console (`server.py`)**: render **7 stage bars**, not 76 rows — each WAITING/RUNNING/PASS/PARTIAL/
  **BLOCKED(reason)**/NA/FAIL; an open-items list; one **"next safest useful action"** (scope gate →
  CI static → seed fixtures → install tool → set preview URL → run staging → triage); fix-it buttons
  (install tool · generate seed command · preview `seed_bedrock.sql` · promote proof→`tests/security/`).
- **Proof→regression:** a `bedrock-pytest`/`bedrock-vitest` wrapper so confirmed proofs run inside the
  user's own CI suite forever.
- **Clean-floor guarantee:** an empty/N-A surface exits **0 in <3s**, every domain-skip *proven* by
  absent assets (benchmarked).

---

## 6. The build roadmap — 4 phases, each shippable, all back-compat

**Phase A — DAG engine** (the biggest leap): add `requires/provides/blocks_if_fail/environments/
safety` to the schema; `graphlib` topological run + `BLOCKED` propagation in `sweep.py`; `--env`
enforcement. *(No new checks; the existing 76 immediately gain ordering + safety.)*

**Phase B — Assets & fixtures:** rewrite Stage-1 FRAME to emit `.bedrock/assets.json`; templates read
it via a loader; ship `seed_bedrock.sql` + the Stripe fixture; enrich `ledger.json` to the evidence schema.

**Phase C — the ~15 IN checks:** add them to the registry in their stages with deps, `safety`, oracles,
and (for adversarial ones) a per-stack proof template. Start with the highest-leverage trio:
`SBA-ANON-001`, `NEXT-RSC-001`, `EDGE-MW-001`.

**Phase D — proof & UX:** the 7-stage DAG console in `server.py`; the fix-it scaffolder; the
proof→regression test-runner wrapper; the clean-floor benchmark.

Each phase is independently shippable and reversible. Missing schema keys default to safe, so the
current 76-check tool keeps working at every step.

---

*Detailed, buildable specs for each area live in `_intake/council/S1-checks-ordering.md`,
`S2-tools-environments.md`, `S3-flow-format-proof.md`. This ROADMAP is the consolidation.*
