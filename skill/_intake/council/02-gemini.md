# COUNCIL VOICE 2 (GEMINI) — Pragmatic Execution & Pruning the Enterprise Bloat

GPT (Voice 1) successfully defined the theoretical "Ultimate" architecture — the DAG, the explicit environments, the asset model, and the lifecycle. However, GPT's vision drifted into **Enterprise CNAPP territory**. 

Solo founders and small teams shipping on Vercel, Supabase, and Stripe do not have Kubernetes clusters, dedicated security teams negotiating SLAs, or the patience for 20 disparate scanning tools (Wiz, Jira syncs, Snyk). If `bedrock-security` becomes a 300-check bureaucracy requiring a week to configure, it will never be run. 

My role is to **cut the enterprise fat**, provide the **concrete implementation details** for GPT's strongest ideas, and inject the harsh **realities of modern serverless SaaS** (Next.js, Supabase, Stripe).

---

## 1. Course Corrections: Cutting the Enterprise Fat

To be the *ultimate* SaaS tool, Bedrock must remain an agile, executable engine, not an audit bureaucracy.

*   **REJECT the Enterprise Tool Zoo:** GPT proposed a matrix of 30+ tools (`trivy`, `kube-score`, `dredd`, `checkdmarc`). Small teams will not install these. We rely on a tight, zero-config core: `semgrep` (for static), `nuclei` (for dynamic), standard test runners (`pytest`/`vitest`), and native ecosystem commands (`npm audit`). Everything else degrades gracefully.
*   **REJECT K8s/Heavy IaC for now:** Target the modern default: Vercel/Render/Fly.io + managed Postgres (Supabase/Neon). Checks should focus on Edge middleware, Vercel `vercel.json` configs, and Postgres RLS, not `kube-apiserver` flags.
*   **REJECT the 9-Stage Sprawl:** GPT's 9 stages are too fragmented for a fast CLI flow. Collapse them into **5 execution environments**: 
    1. **FRAME** (Asset generation)
    2. **STATIC** (Pre-commit/CI: Semgrep, Gitleaks)
    3. **PREVIEW** (Ephemeral URL: passive dynamic, CORS, headers)
    4. **STAGING** (Seeded Data: BOLA, Race, Webhooks)
    5. **PROD** (Strictly Read-Only/Passive)
*   **REJECT Jira/SLA Bureaucracy:** The ledger (`.bedrock/LEDGER.md` + `.bedrock/ledger.json`) *is* the single source of truth. We do not need SARIF exports or ticket-syncing. If it's RED in the ledger, the CI fails. That is the SLA.

---

## 2. Implementation: The Asset Model & Fixture Seeding

GPT correctly identified that `FRAME` must output an asset model. Here is exactly how `assets.json` works and how it seeds the Staging environment.

### A. The `.bedrock/assets.json` Schema
`sweep.py`'s Stage 0 (Frame) parses the codebase and emits this state file. The templates in `templates/` consume this directly instead of requiring human hardcoding.

```json
{
  "target": "https://staging.my-saas.com",
  "tenants": {
    "A": { "id": "t_123", "token_env": "TEST_TOKEN_A" },
    "B": { "id": "t_456", "token_env": "TEST_TOKEN_B" }
  },
  "roles": ["owner", "member", "anonymous"],
  "resources": [
    { "type": "invoice", "path": "/api/invoices/{id}", "auth_required": true, "owner_field": "tenant_id" }
  ],
  "webhooks": [
    { "provider": "stripe", "path": "/api/webhooks/stripe", "secret_env": "STRIPE_WH_SEC" }
  ]
}
```

### B. Seeded Fixtures for Serverless SaaS
To run BOLA or Race checks automatically, we need data.
*   **Supabase/Postgres:** `sweep.py` provides a standard `seed_bedrock.sql` that injects Tenant A, Tenant B, and dummy rows, wrapped in a transaction that rolls back after the sweep.
*   **Stripe/Billing:** Rely on Stripe CLI's native fixture support (`stripe fixtures`). Bedrock includes a standard `bedrock-stripe-fixture.json` that generates a test customer and subscription, which the webhook tests then attack (replays, duplicate IDs, signature stripping).

---

## 3. Implementation: DAG Resolution & Tool Degradation

GPT asked for a dependency DAG. Here is how `sweep.py` implements it without becoming a massive orchestrator like Airflow.

### A. Topological Sort in `sweep.py`
The `registry.yaml` gets new keys: `requires` and `provides`.
`sweep.py` builds a simple directed graph using Python's `graphlib.TopologicalSorter`. 
If a check fails, all downstream checks are marked `BLOCKED`, saving time and noise. 

```python
# engine/runner.py pseudo-code
try:
    for check_id in TopologicalSorter(dag).get_ready():
        if is_blocked(check_id):
            continue
        result = execute_check(check_id, assets)
        if result == FAIL:
            mark_downstream_blocked(check_id)
```

### B. Graceful Tool Degradation (The Adapter Pattern)
Instead of failing when a user lacks a tool, the "Tool Adapter" degrades via a `strategy` array.
*Example: Secret Scanning (`SEC-LEAK-001`)*
1. **Attempt 1 (Ideal):** `trufflehog git file://.`
2. **Attempt 2 (Fallback):** `gitleaks detect`
3. **Attempt 3 (Baseline):** `git grep -E '(?i)(secret|token|key)'` 
4. **Attempt 4 (Manual):** Emit `NEEDS-PROOF` and prompt the user.

---

## 4. Additions: The Missing Serverless SaaS Realities

GPT missed the specific attack vectors of the modern Next.js/Supabase stack. We must add these exact checks:

1.  **`NEXT-RSC-001` (React Server Components Leak):** 
    *   *Risk:* Passing entire database user objects from server to client components in Next.js App Router, exposing password hashes/PII in the `__next_f` script tags.
    *   *Proof:* Semgrep rule looking for `select *` passed directly to a `"use client"` component prop.
2.  **`EDGE-MW-001` (Edge Middleware Auth Bypass):** 
    *   *Risk:* Next.js middleware enforcing auth based on URL paths (`/dashboard/:path*`), but bypassed via internal rewrites or casing differences (`/Dashboard`). 
    *   *Proof:* Fuzzing restricted routes with casing and path traversal tricks to bypass `matcher`.
3.  **`SBA-ANON-001` (Supabase Anon Key Abuse):** 
    *   *Risk:* Exposing the `NEXT_PUBLIC_SUPABASE_ANON_KEY`, but failing to enable RLS on a table, allowing instant full-database compromise via the client SDK.
    *   *Proof:* Static check: Any table missing RLS + Anon key present.
4.  **`LLM-BLIND-001` (Blind SSRF via LLM Tools):**
    *   *Risk:* Giving an LLM a "fetch_url" tool without egress filtering, allowing the user to prompt the LLM to read internal AWS metadata or local host files.
    *   *Proof:* Adversarial prompt attempting to hit `http://169.254.169.254` via the model.

---

## 5. The Top 12 Leverage Points (Dependency Ordered)

Here is the ruthless prioritization to build the ultimate, zero-bloat version of `bedrock-security`.

**PHASE A: CORE MACHINERY (The Engine)**
1.  **DAG Orchestration:** Update `sweep.py` to use `requires`/`provides` and `graphlib` to ensure `INV-001` blocks `BOLA-001`.
2.  **Asset Model Generation (`assets.json`):** Rewrite Stage 0 to output a strict JSON schema of routes, roles, and secrets instead of prose. 
3.  **Tool Adapter Degradation:** Implement the fallback execution engine (e.g., Try Semgrep -> Try Regex -> Fail to Manual).
4.  **Env Safety Rails:** Add `--env=preview|staging|prod` to `sweep.py`. Hardcode flags on checks (`destructive: true`, `safe_in_prod: false`) so the runner refuses to execute RACE or BOLA against production.

**PHASE B: SERVERLESS & NEXT-GEN CHECKS (The Registry)**
5.  **Supabase/Postgres Automation:** Add deep `psql`/REST introspection to auto-verify `SUPABASE-RLS-001` instead of relying on manual SQL templates.
6.  **Next.js/React AppSec:** Add the `NEXT-RSC-001` and `EDGE-MW-001` checks to the registry with precise Semgrep rules.
7.  **Webhook Fixture Suite:** Ship a standard `mitmproxy` or Stripe CLI script to automate `WEBHOOK-001` (replay, bad sig, idempotency) without hand-writing Python.
8.  **LLM Tool Safety:** Add `LLM-BLIND-001` (SSRF via tools) and `LLM-RAG-TENANT-001` (cross-tenant RAG leakage) to the AI phase.

**PHASE C: DEVELOPER EXPERIENCE (The UX)**
9.  **The "Fix-It" Scaffolder:** When `sweep.py` finds a missing Kill-Switch or missing RLS, it should offer to generate the `.sql` or `.ts` patch and apply it. Don't just complain; fix.
10. **Live Console Visualization:** Update `server.py` to render the DAG visually. Show users exactly *why* a check is blocked (e.g., "Waiting on Tenant Fixtures").
11. **Test-Runner Integration:** Instead of standalone templates, wrap the adversarial proofs into a `bedrock-jest` or `bedrock-pytest` plugin so they run inside the user's existing CI test suite.
12. **The "Clean Floor" Guarantee:** Formalize the rule that an empty/N-A codebase exits 0 in under 3 seconds. The tool must feel lighter than air when nothing is wrong.
