# COUNCIL VOICE 3 (CLAUDE) — THE CONSOLIDATED ELEVATION BLUEPRINT

> Synthesis of GPT (enterprise-complete) and Gemini (ruthless-pragmatic), resolved for an
> owner who ships **real SaaS on Vercel/Supabase/Stripe** and wants the **ultimate tool**.
> This is the build contract. Decisive calls, not options.

---

## 1. THE VERDICT — the unifying philosophy

**"Ultimate" is not "most checks" — it is the shortest path from an unframed repo to a
provably-secure release, with zero wasted motion and zero bloat that gets the tool turned
off.** GPT is right that bedrock must become a *dependency-aware, asset-driven, evidence-
producing engine* (a DAG, not a list); Gemini is right that it must stay a *zero-config CLI
that runs in 3 seconds on a clean repo and degrades gracefully when a tool is missing*. The
synthesis resolves the tension on a single axis — **depth-on-demand**: every powerful idea
GPT proposed (asset model, evidence schema, env safety rails, the new tenant/billing/LLM
checks) is built into the *engine and registry schema* so the ceiling is enterprise-grade,
but it stays *dormant and free* until the target's surface actually triggers it. The
inventory creates assets → assets generate tests → tests run only in safe environments →
the tightest possible tool core produces evidence → evidence drives the gate. We add the
~15 checks that a solo SaaS founder genuinely gets breached by (RLS-off, RSC leaks, billing
webhooks, cross-tenant cache/RAG, edge-middleware bypass) and we **reject the CNAPP zoo**
(K8s, multi-cloud IAM benchmarks, SLA/Jira lifecycle) that no two-person team will ever
run. The ledger stays the single source of truth; the gate stays the SLA. **Comprehensive
where a real SaaS bleeds; ruthless everywhere else.**

---

## 2. THE STAGE MODEL — final ordered stages + the DAG

### The resolution: 7 stages (GPT's 9 collapsed, Gemini's 5 expanded by 2 that earn their keep)

GPT's 9 fragments the flow; Gemini's 5 conflates "where it runs" (environment) with "what
phase it is" (logical step). **The fix: stages are a logical pipeline; environment is an
orthogonal tag.** We keep GPT's two genuinely load-bearing splits — **SCOPE/SAFETY** as a
hard gate before any adversarial execution (you must not test a target you don't own / in
prod) and **ARTIFACT** as distinct from source-static (built JS leaks what source doesn't) —
and collapse the rest. Gemini's "5 environments" become the **`environments[]` safety tag**
in §4, not stages.

| # | Stage | Replaces (GPT / Gemini) | Existing check ids that map here |
|---|---|---|---|
| **0** | **SCOPE & SAFETY** | GPT St0 / (Gemini implicit) | `INV-007`, `DEPLOY-GATE-001`, **+new** `SCOPE-001`, `DATA-SAFETY-001` |
| **1** | **FRAME** (asset gen) | GPT St1 / Gemini FRAME | `INV-008`, `INV-001`, `APIINV-001`, `INV-005`, `INV-002`, `INV-003`, `INV-004`, `INV-006` |
| **2** | **STATIC** (pre-commit + CI + artifact) | GPT St2+3 / Gemini STATIC | `SEC-LEAK-001`, `ENV-001`, `ENV-002`, `PATTERN-003`, `PATTERN-004`, `PATTERN-001`, `PATTERN-002`, `DEP-001/002/003`, `REDOS-001`, `FLOOR-A03/A05/A08/A09/A02`, `CLIENT-ENV-001`, `SOURCEMAP-001`, `COOKIE-FLAGS-001`, `CLICKJACK-001`, `HDR-001/002`(static posture), `CISEC-001`, `TEST-ISO-001`, `DOC-FRESH-001`, **+new** `SBA-ANON-001`, `NEXT-RSC-001`, `IAC-001`(opt) |
| **3** | **DYNAMIC-PASSIVE** (preview/prod-readonly) | GPT St4 / Gemini PREVIEW+PROD | `HDR-001/002`(live), `CLICKJACK-001`(live), `COOKIE-FLAGS-001`(live), `SOURCEMAP-001`(live), `ERRORLEAK-001`, `AUTHN-REQUIRED-001`, `SIZE-001`, `PAGINATION-001`, **+new** `DMARC-001`, `CERT-001`, `DNS-001` |
| **4** | **DYNAMIC-ADVERSARIAL** (seeded staging) | GPT St5+6+7 / Gemini STAGING | `AUTHZ-SERVER-001`, `BOLA-001`, `BFLA-001`, `MASS-001`, `EXCESSDATA-001`, `SUPABASE-RLS-001`, `TENANT-DEL-001`, `AUDIT-001`, `PATHTRAV-001`, `REDIRECT-001`, `WEBSOCKET-001`, `JWT-001`, `JWT-002`, `TOKEN-ROTATE-001`, `OAUTH-001`, `PWPOLICY-001`, `LOCK-001`, `ACCT-VERIFY-001`, `AUTH-STORAGE-001`, `TIMING-001`, `INJ-001`, `XXE-001`, `SSTI-001`, `NOSQLI-001`, `HOSTHDR-001`, `SSRF-001`, `WEBHOOK-001`, `IDEM-001`, `RACE-001`, `RATE-001`, **+new** `EDGE-MW-001`, `BILLING-WEBHOOK-001`, `ENTITLEMENT-001`, `CACHE-TENANT-001`, `SEARCH-TENANT-001` |
| **5** | **LLM/AI** | GPT St8 / Gemini (folded) | `LLM-INJ-001`, `LLM-OUT-001`, `LLM-FAILOPEN-001`, **+new** `LLM-BLIND-001`, `RAG-TENANT-001` |
| **6** | **DECISION / TRIAGE / VERDICT** | GPT St9 / Gemini (ledger) | `DEC-001`, `DEC-002`, `CSRF-001`, `TRIAGE-001`, `TEST-ISO-001`(verdict), `DOC-FRESH-001`, `DEPLOY-GATE-001`(final) |

> **Why LLM/AI is its own stage (5) and not folded into 4:** it is the only adversarial
> family that is *cost-generating* and needs a mocked tool-layer/model-gateway before it can
> run safely. Isolating it lets the runner skip it cleanly (and instantly) on the 90% of
> repos with no model surface — Gemini's "lighter than air when nothing is wrong" rule.

### The DAG — four edge types on every check record

GPT's `requires/unlocks/blocks_if_fail` + Gemini's `graphlib.TopologicalSorter` is the
right machinery. Final schema keys (engine resolves with stdlib `graphlib`, no Airflow):

```yaml
requires:        [INV-001, INV-005]     # hard deps — check is BLOCKED until these PASS/produce assets
provides:        [assets.routes, assets.tenant_resources]   # what it writes to assets.json
blocks_if_fail:  true                    # if this FAILs, mark all downstream `requires`-ers BLOCKED (not run)
environments:    [staging, preview]      # safety rail (see §4) — runner refuses other envs
```

**The load-bearing dependency edges** (from the snapshot's real ids — these are the ones
that make the order *non-wasteful*):

- `INV-001` → unlocks `AUTHN-REQUIRED-001`, `AUTHZ-SERVER-001`, `BOLA-001`, `BFLA-001`, `MASS-001`, `EXCESSDATA-001`, `PATHTRAV-001`, `REDIRECT-001`, `WEBSOCKET-001`, `INJ-001`, `PAGINATION-001`, `EDGE-MW-001`
- `INV-005` → unlocks `SUPABASE-RLS-001`, `SBA-ANON-001`, `TENANT-DEL-001`, `AUDIT-001`, `RACE-001`, `CACHE-TENANT-001`, `SEARCH-TENANT-001`
- `INV-002` → unlocks `JWT-001`/`002`, `TOKEN-ROTATE-001`, `OAUTH-001`, `COOKIE-FLAGS-001`, `AUTH-STORAGE-001`, `ACCT-VERIFY-001`, `PWPOLICY-001`, `LOCK-001`
- `INV-003` → unlocks `SSRF-001`, `WEBHOOK-001`, `BILLING-WEBHOOK-001`, `IDEM-001`, `TIMING-001`
- `INV-006` → unlocks `LLM-INJ-001`, `LLM-OUT-001`, `LLM-FAILOPEN-001`, `LLM-BLIND-001`, `RAG-TENANT-001`
- `INV-004` → unlocks `SEC-LEAK-001`, `ENV-001/002`, `PATTERN-003`, `FLOOR-A09`, `ERRORLEAK-001`
- **Hard gate:** `SCOPE-001` + `DEPLOY-GATE-001` **block the entire DYNAMIC-* and LLM stages** — no live probe fires until target ownership + environment + rollback are confirmed.
- **Critical ordering inside Stage 4:** `AUTHN-REQUIRED-001` → `BOLA-001` (anon-access makes object-authz moot); `JWT-001` → `JWT-002` (broken sig validation invalidates purpose conclusions); `WEBHOOK-001` → `IDEM-001` → `RACE-001` (signature, then dup-delivery, then concurrency compose); `SIZE-001` → all fuzzing (don't DoS yourself).

---

## 3. THE ADDITIONS — decisive IN / DEFER / REJECT

Honest filter applied: **"Does a solo/small-team SaaS on Vercel+Supabase+Stripe get breached
by this, or is it CNAPP theater?"** IN = build now. DEFER = schema-ready, dormant, ships when
a surface triggers it (zero cost if absent). REJECT = out of scope for this product.

### Serverless / Next.js / Supabase (Gemini's domain) — **the highest-leverage additions**
| Check | Verdict | One-line rationale |
|---|---|---|
| `SBA-ANON-001` (anon key + RLS-off) | **IN** | The #1 Supabase breach: public anon key + one RLS-off table = full DB dump. Cheap static check, catastrophic miss. |
| `NEXT-RSC-001` (RSC→client object leak) | **IN** | App Router hands whole DB rows (hashes/PII) to the client in `__next_f`. Endemic, invisible, semgrep-detectable. |
| `EDGE-MW-001` (middleware auth bypass) | **IN** | `matcher`-based auth bypassed by casing/rewrite is a real Next.js footgun; fuzz restricted routes. |
| `LLM-BLIND-001` (blind SSRF via LLM tool) | **IN** (in Stage 5) | A `fetch_url` tool with no egress filter → `169.254.169.254`. Real for any AI-feature SaaS. |

### Multi-tenant derived-data (GPT) — **IN where the owner's stack actually has the surface**
| Check | Verdict | Rationale |
|---|---|---|
| `CACHE-TENANT-001` | **IN** | Vercel/Next caching cross-tenant responses is a one-line bug with total-leak blast radius. |
| `SEARCH-TENANT-001` | **IN** (DEFER if no search) | Tenant filter dropped server-side in search/autocomplete; gated on a search index existing. |
| `RAG-TENANT-001` | **IN** (Stage 5, gated on `INV-006`) | Vector search without a tenant filter = tenant B's docs to tenant A. Core AI-SaaS risk. |
| `EXPORT-TENANT-001` | **DEFER** | Real but a variant of BOLA+EXCESSDATA; fold into those until an export route is inventoried. |
| `SUPPORT-IMPERSONATION-001` | **DEFER** | Matters once a support plane exists; most solo SaaS has none yet. Dormant, schema-ready. |

### Billing / entitlements (GPT) — **IN; this is where SaaS loses money**
| Check | Verdict | Rationale |
|---|---|---|
| `BILLING-WEBHOOK-001` | **IN** | Stripe sig-verify + out-of-order/duplicate event → wrong entitlement. The owner runs Stripe; non-negotiable. |
| `ENTITLEMENT-001` | **IN** | Client-side plan flags forged / tenant B uses tenant A subscription. Server-trust check, high value. |
| `TRIAL-ABUSE-001` | **DEFER** | Real revenue leak but business-logic-specific; schema-ready, not core-path. |

### Admin plane / identity (GPT)
| Check | Verdict | Rationale |
|---|---|---|
| `ADMIN-001` (admin route hard authz) | **IN** | Folds naturally into `BFLA-001`'s role matrix; cheap, high value once an admin role exists. |
| `MFA-001` (MFA for privileged) | **DEFER** | Important but policy/config-level; flag as decision, don't block a solo founder's first release. |
| `RBAC-MATRIX-001` | **REJECT as separate** | Subsumed by `BFLA-001` + `INV-001` role matrix; a standalone matrix check is duplicate bureaucracy. |

### DNS / email / TLS (GPT) — **IN; cheap, prod-readonly-safe, real**
| Check | Verdict | Rationale |
|---|---|---|
| `DMARC-001` (SPF/DKIM/DMARC) | **IN** | One DNS lookup; missing DMARC = spoofable transactional email. `checkdmarc` or stdlib DNS. |
| `CERT-001` (TLS/HSTS posture) | **IN** | Passive, prod-safe; `sslyze`/`testssl` optional, degrades to a stdlib TLS handshake probe. |
| `DNS-001` (subdomain takeover) | **IN** (light) | Dangling preview CNAMEs are a real Vercel hazard; light `dnsx`/CNAME-resolve, no heavy toolchain. |

### Queues / async (GPT)
| Check | Verdict | Rationale |
|---|---|---|
| `QUEUE-AUTHZ-001` / `QUEUE-IDEM-001` | **DEFER** | Real, but serverless SaaS often has no worker tier yet; schema-ready, fires only if a queue is inventoried. |
| `EMAIL-SMS-001` | **DEFER** | Fold reset/invite expiry into `TOKEN-ROTATE-001`/`LOCK-001`; standalone only when an SMS surface exists. |

### Cloud / IaC / container / runtime (GPT) — **the CNAPP zoo; mostly REJECT for this product**
| Check | Verdict | Rationale |
|---|---|---|
| `IAC-001` (Terraform/IaC misconfig) | **DEFER (opt-in)** | Only fires if `*.tf`/`vercel.json`/compose present; `trivy config`/`checkov` optional. Vercel users rarely have TF. |
| `IAM-001` (cloud IAM least-priv) | **REJECT** | Cloudsplaining/Prowler/multi-cloud benchmarks = enterprise CNAPP. Not a Vercel/Supabase reality. |
| `STORAGE-001` (bucket isolation) | **DEFER** | Reframe narrowly as *Supabase Storage RLS* under `SUPABASE-RLS-001`; reject the generic S3/bucket-policy scanner. |
| `CONTAINER-001/002`, `K8S-001` | **REJECT** | No containers/K8s on the target stack. Pure bloat; Gemini is right. |
| `SBOM-001`, `SIGN-001`, `PROVENANCE-001`, `LICENSE-001`, `SCORECARD` | **REJECT** | Supply-chain provenance theater for a 2-person team. `DEP-001/002/003` already cover the real risk. |

### Data governance / observability / IR (GPT)
| Check | Verdict | Rationale |
|---|---|---|
| `ANALYTICS-PII-001` (planted secret in Sentry/PostHog) | **IN** | Cheap, high-signal; folds into `LLM-OUT-001`/`FLOOR-A09` planted-secret machinery. Real leak path. |
| `PII-INV-001` (data classification) | **DEFER** | Useful asset-model enrichment, not a gate; let `INV-005` carry coarse labels, defer full classification. |
| `RETENTION-001`, `BACKUP-RESTORE-001` | **DEFER (evidence-only)** | Backups exist on Supabase by default; verify-only, never a blocking adversarial test. |
| `KEY-ROTATE-001` | **DEFER** | Decision/runbook-level; pairs with `DEC-002` kill-switches, not a first-release blocker. |
| `ALERT-001`, `RUNBOOK-001` | **DEFER** | Ops maturity, not appsec proof; keep as optional decision records. |

### Finding lifecycle (GPT's Gap 8) — **the GPT-vs-Gemini fault line; split the difference**
| Capability | Verdict | Rationale |
|---|---|---|
| JSON evidence ledger + schema (`ledger.json` enrichment) | **IN** | The evidence schema *is* the proof discipline; deepen the existing `ledger.json`. |
| Generated regression test per fixed critical/high | **IN** | "Proof→regression" is the north-star payoff and cheap once a template ran. |
| SARIF export | **DEFER** | One small adapter; ships when the owner wires CI annotations. Not core. |
| Suppression-with-expiry, owner, severity-SLA, Jira/Linear sync | **REJECT** | Audit-bureaucracy for a team that doesn't exist. The ledger RED *is* the SLA (Gemini). |

**Net:** **~15 IN** (the real SaaS bleed-points), **~14 DEFER** (schema-ready, dormant, zero-
cost-if-absent), **~10 REJECT** (the CNAPP/bureaucracy zoo). The flat 76 → ~91 *defined*,
but only those whose surface exists ever execute.

---

## 4. THE TOOL & ENVIRONMENT MODEL

### The tool-adapter core (Gemini's tight core wins; GPT's zoo becomes optional tiers)

**Mandatory zero-config core (4):** `semgrep` (static/SAST + the new RSC/anon/edge rules),
`nuclei` (dynamic headers/misconfig/SSRF templates), the project's **own test runner**
(`pytest`+`httpx` / `vitest`+`supertest`) for adversarial proofs, and **native ecosystem
audit** (`npm audit`/`pip-audit`/`osv-scanner` — whichever the stack has). Plus `gitleaks`
for secrets (with the degradation ladder below). **Everything else is an optional adapter**
the runner detects and uses if present, else degrades.

**The adapter degradation ladder** (Gemini's pattern — every tool-backed check carries a
`strategy[]`, runner walks it top-down, first available wins, last rung is always
`NEEDS-PROOF` + the exact command printed):

```yaml
# e.g. SEC-LEAK-001
strategy:
  - {tool: trufflehog,  cmd: "trufflehog git file://. --only-verified"}   # ideal (verified)
  - {tool: gitleaks,    cmd: "gitleaks detect --source . --redact"}        # strong
  - {tool: ripgrep,     cmd: "rg -i '(secret|token|api[_-]?key|password)\\s*[:=]'"}  # baseline
  - {tool: manual,      emit: NEEDS-PROOF}                                  # never a silent skip
```

Optional adapters, used-if-present, never required: `trufflehog`, `osv-scanner`/`trivy`,
`jwt_tool`, `Playwright` (browser storage/CORS checks), `k6` (capped concurrency for
`RACE-001`), `interactsh`/canary (OOB SSRF), `stripe` CLI (webhook fixtures), `sslyze`/
`testssl` (`CERT-001`), `checkdmarc`/`dnsx` (`DMARC-001`/`DNS-001`), `checkov`/`trivy config`
(`IAC-001`, opt-in). **Explicitly NOT adopted:** ZAP/Burp/sqlmap/garak/Wiz/Snyk as
*required* — they may be invoked manually but are not in the runnable core (too heavy /
licensed / slow for the 3-second clean-floor promise).

### The env safety rails — five flags on every check

Every check record carries these (GPT's safety rails, Gemini's `--env` enforcement):

```yaml
safety:
  destructive:     false   # mutates/deletes state
  cost_generating: false   # bills (LLM tokens, paid webhooks, SMS)
  needs_seed_data: false   # requires tenant A/B fixtures
  readonly:        true    # pure read/probe
  safe_in_prod:    true    # may run against production
```

`sweep.py --env=<preview|staging|prod>` **refuses** to execute any check whose `safety`
contradicts the env (e.g. `RACE-001` is `destructive:true, safe_in_prod:false` → blocked in
prod; `HDR-001` is `readonly:true, safe_in_prod:true` → always allowed).

### The 5-environment mapping (Gemini's environments, now a tag not a stage)

| Environment | Allowed safety profile | Checks (by id) |
|---|---|---|
| **pre-commit** | readonly, fast, no-net | `SEC-LEAK-001`, `ENV-001/002`, `PATTERN-003/004`, `REDOS-001`, `FLOOR-A03/A08`, `CLIENT-ENV-001`, `SBA-ANON-001`(static), `NEXT-RSC-001` |
| **CI** | readonly + build-artifact | all pre-commit + `DEP-001/002/003`, `CISEC-001`, `PATTERN-001/002`, `FLOOR-A05/A09`, `SOURCEMAP-001`, `COOKIE-FLAGS-001`(static), `TEST-ISO-001`, `DOC-FRESH-001`, `IAC-001`(if present) |
| **preview** (ephemeral URL) | readonly dynamic, `safe_in_prod` ok | `HDR-001/002`, `CLICKJACK-001`, `COOKIE-FLAGS-001`(live), `ERRORLEAK-001`, `AUTHN-REQUIRED-001`, `SIZE-001`, `PAGINATION-001`, `EDGE-MW-001`(passive) |
| **staging** (seeded) | `needs_seed_data`, `destructive` ok, **not** prod | all of Stage 4 + Stage 5: `BOLA/BFLA/MASS/RLS/TENANT-DEL/JWT/OAUTH/LOCK/RACE/RATE/SSRF/WEBHOOK/BILLING-WEBHOOK/ENTITLEMENT/CACHE/SEARCH/RAG-TENANT/LLM-*` |
| **prod** (read-only) | `readonly:true, safe_in_prod:true` ONLY | `HDR-001/002`, `CLICKJACK-001`, `SOURCEMAP-001`, `COOKIE-FLAGS-001`, `FLOOR-A02`, `CERT-001`, `DMARC-001`, `DNS-001`, `APIINV-001`(passive), `AUDIT-001`(config-read) |

---

## 5. THE IMPLEMENTATION ROADMAP — dependency-ordered build steps

Build in this order; each phase is independently shippable and the engine stays runnable
throughout (no big-bang rewrite).

**PHASE A — Engine becomes a DAG (the "list → programme" leap):**
1. **`registry.yaml` schema bump:** add `requires`, `provides`, `environments`, `safety{}`,
   `strategy[]` keys to the record schema (back-compat: missing keys = no-dep, all-env,
   readonly defaults — existing 76 keep working). Update `engine/README.md` schema doc.
2. **`sweep.py` DAG resolution:** build the graph from `requires`/`provides`, order with
   stdlib `graphlib.TopologicalSorter`; on a check FAIL with `blocks_if_fail:true`, mark
   downstream `BLOCKED` (new ledger state) instead of running them.
3. **`sweep.py --env` rail:** add the flag; before executing any check, assert its `safety`
   is compatible or skip with a `BLOCKED(env)` reason. Default `--env=preview` (safe).
4. **Clean-floor guarantee:** short-circuit — if FRAME produces an empty asset surface for a
   domain, all its checks resolve N/A instantly. Assert `<3s` exit on an empty repo (test).

**PHASE B — FRAME produces assets (everything downstream depends on it):**
5. **`assets.json` emitter:** rewrite Stage 0 (`INV-001..008`) to write
   `.bedrock/assets.json` (routes, roles, token_types, tenant_resources, external_fetches,
   webhooks, llm_surfaces, datastores, secrets, deploy_targets) — not prose. Schema in S2 brief.
6. **Templates consume assets:** point existing `templates/<stack>/*` at `assets.json` (read
   routes/identities from it) instead of hardcoded placeholders.
7. **Fixture seeding:** ship `templates/supabase-postgres/seed_bedrock.sql` (tenant A/B + dummy
   rows, `begin;…rollback;`) and a Stripe-CLI `bedrock-stripe-fixture.json`.

**PHASE C — The IN checks (the real SaaS bleed-points):**
8. Add static IN checks with semgrep rules: `SBA-ANON-001`, `NEXT-RSC-001`, `EDGE-MW-001`
   (static portion). Add to registry + `templates/`.
9. Add adversarial IN checks + templates: `BILLING-WEBHOOK-001`, `ENTITLEMENT-001`,
   `CACHE-TENANT-001`, `SEARCH-TENANT-001`, `ADMIN-001` (fold into BFLA matrix),
   `ANALYTICS-PII-001`.
10. Add Stage-5 IN checks: `LLM-BLIND-001`, `RAG-TENANT-001` + templates.
11. Add prod-readonly IN checks: `DMARC-001`, `CERT-001`, `DNS-001` (with degradation to
    stdlib DNS/TLS probes).
12. Register the DEFER checks **as dormant records** (`environments`/`requires` gate them so
    they're invisible unless their surface is inventoried) — schema-ready, zero runtime cost.

**PHASE D — Proof & UX (close the loop):**
13. **Deepen `ledger.json`** to the evidence schema (`tool`, `command`, `observed`,
    `expected`, `negative_control`, `evidence_files`, `started/ended_at`).
14. **`server.py` DAG view:** render stage progress + *why a check is BLOCKED* ("waiting on
    tenant fixtures" / "needs `--env=staging`"), not 76 flat rows.
15. **Proof→regression:** on a green adversarial proof, offer to copy it into the project's
    own test suite (`tests/security/`) so it guards every future release.
16. **Add the 4 new Stage-0 records** (`SCOPE-001`, `DATA-SAFETY-001`) and wire them as the
    hard gate blocking all DYNAMIC/LLM stages.

---

## 6. THE 3 SECTION BRIEFS (for the Sonnet squad)

**S1 — "Checks & Ordering"**
Own the final 7-stage model + the DAG. Produce the complete `requires`/`provides`/
`blocks_if_fail`/`environments` edge list for **all 76 existing + every IN/DEFER** check
(use the real ids and edges in §2). Write the precise registry placement (stage + deps) for
each of the ~15 IN additions and mark each DEFER record dormant via its gate. Deliver the
authoritative ordering table and the critical intra-stage sequence rules
(AUTHN→BOLA, JWT-001→002, WEBHOOK→IDEM→RACE, SIZE→fuzz, SCOPE/DEPLOY-GATE block all live).

**S2 — "Tools, Software & Environments"**
Own the tool-adapter core + degradation + env rails. Specify the 4-tool mandatory core and
the optional-adapter detection logic; write the `strategy[]` ladder for every tool-backed
check (secrets, deps, dynamic, JWT, SSRF, billing, DNS/TLS). Define the `safety{}` flag
values for **all** checks and the `--env` enforcement matrix; deliver the final 5-environment
→ check-id mapping (§4) and the "explicitly NOT in core" exclusion list with rationale.

**S3 — "Flow, Format, Protocol & Proof/UX"**
Own the data/flow/UX surface. Specify the `.bedrock/assets.json` JSON schema (every asset
type + fields); the fixture-seeding contract (`seed_bedrock.sql` + Stripe fixture, rollback-
wrapped); the enriched `ledger.json` evidence schema (observed/expected/negative_control/
tool/command/timestamps); the `server.py` DAG-progress console (stage bars, BLOCKED-reasons,
next-safest-action); the proof→regression test-runner integration; and formalize the
clean-floor guarantee (empty surface → exit 0 in <3s, every domain skip proven by absent assets).

---

# BOTTOM LINE
The elevation is **not** +200 checks and a CNAPP suite (GPT over-reached) nor a thin
5-stage CLI that ignores billing/RAG/RSC leaks (Gemini under-reached). It is: a **DAG engine
with an asset model and env safety rails** (deep, GPT) that ships a **tight 4-tool core with
graceful degradation and a 3-second clean floor** (lean, Gemini), carrying **~15 surgically
chosen new checks** for exactly how a Vercel/Supabase/Stripe SaaS actually gets breached —
and nothing the owner will never run. Depth on demand; ruthless by default.
