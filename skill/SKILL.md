---
name: bedrock-security
description: >
  Second-order application security playbook — the hardening, testing, and
  decision-making that comes AFTER the obvious OWASP/checklist pass. Auto-fire
  whenever the user is setting up, reviewing, hardening, or testing the security
  of an app/API/service: authn/authz, rate limiting, secrets & env management,
  multi-tenant isolation (BOLA/IDOR), billing/quota race conditions, login
  lockout, JWT hardening, security headers, LLM/AI guardrails & prompt-injection,
  CI security tests, and secure deploy/ops. Use it when generic "use HTTPS,
  hash passwords, parameterize queries" advice is NOT enough — when the goal is
  production-grade, adversary-tested security with falsifiable tests and explicit
  fail-open/fail-closed decisions. Runs as an executable system: a machine-readable
  check registry, a runner (engine/sweep.py) that frames the target and gates the
  result, a forced step-by-step procedure (PROTOCOL.md), and per-stack proof
  templates — it PROVES each applicable control rather than claiming it, and skips
  nothing unless proven not-applicable.
triggers:
  - cybersecurity
  - security setup
  - secure my app
  - harden
  - hardening
  - security review
  - security audit
  - penetration
  - pentest
  - threat model
  - rate limit
  - rate limiting
  - bola
  - idor
  - broken access control
  - multi-tenant security
  - secrets management
  - env vars
  - environment variables
  - jwt
  - auth security
  - login lockout
  - brute force
  - prompt injection
  - llm security
  - ai guardrails
  - guardrails
  - security testing
  - security tests
  - owasp
  - secure deploy
  - api security
---

# Bedrock Security

**The security layer that comes *after* the obvious checks.**

Generic security advice (use HTTPS, hash passwords, parameterize queries, follow
OWASP Top 10) is the floor, not the ceiling. This skill encodes the *second-order*
practices that separate "passed a checklist" from "survives a motivated attacker
and a 3am incident" — earned the hard way shipping a real multi-tenant SaaS to
production.

## How to use this skill — run the system, don't freestyle

This skill is an **executable enforcement system**, not just a reading. When the
task is a security sweep / audit / hardening / "is this secure?", you run it:

> **Two ways to run it:**
> - **The console (live local app):** `python engine/server.py <target>` opens a UI in
>   the browser that walks **every** check live — green = applies, red = N/A, amber =
>   judgement — lets you **ADD / REMOVE / approve** the selection, then runs the proofs
>   on the approved set, all streamed. Same registry, same gate. (`ui/index.html`.)
> - **Headless:** `python engine/sweep.py <target>` for CI / a one-shot gated ledger.

1. **Drive it with `PROTOCOL.md`.** The forced, ordered procedure — Frame →
   Applicability → Static → Adversarial → Decision → Triage → Verdict. Top to bottom;
   you do not skip stages and you do not declare "secure" until its §7 bar passes.
2. **Run the engine.** `python engine/sweep.py <target>` frames the attack surface,
   runs every static probe, and emits a **gated ledger** (`.bedrock/LEDGER.md`): one
   row per check — APPLICABLE? · PASS / FAIL / N-A / NEEDS-PROOF · evidence · oracle.
   It **exits non-zero while any applicable check is unproven** — that exit code is
   the enforcement. (`engine/registry.yaml` is the single source of truth for all
   checks; `engine/README.md` explains the schema and probe types.)
3. **Close every OPEN item with PROOF, not a claim.** For each applicable adversarial
   check, copy its per-stack template from `templates/`, wire it to the real routes
   from the frame, and run it. PASS requires an *artifact* — a passing falsifiable
   test, a live probe, a command exit, or a cited `file:line`. Never "I reviewed it."
4. **Pull the reference doc** for the depth behind any check (don't load all five at
   once):
   - `references/security-testing-methodology.md` — how to *prove* security with
     falsifiable, isolated tests (and why your own tests lie to you by default).
   - `references/hardening-playbook.md` — the core controls + their non-obvious
     failure modes (BOLA status leaks, rate-limit bypasses, race conditions, JWT,
     lockout, headers, CWE-532).
   - `references/more-controls.md` — SSRF, inbound webhook signature verification,
     timing-safe comparison, idempotency keys, request-size/decompression limits,
     dependency/supply-chain, audit-log integrity, CSRF/cookie nuance for SPAs.
   - `references/ai-llm-security.md` — prompt-injection, output scrubbing, fail-open
     guards, kill-switches, and cost-aware escalation (cheap regex → managed guardrails).
   - `references/secrets-and-ops.md` — secrets/env storage, deploy footguns, and the
     fail-open vs fail-closed decision.
   - `references/framework-mappings.md` — every check crosswalked to OWASP Top 10 /
     API Top 10, MITRE ATT&CK, NIST CSF, D3FEND, ATLAS, AI RMF (compliance reporting).
   - `references/cyber-skills-catalog.md` — the 754-skill DFIR/offensive corpus
     (mukul975, Apache-2.0) captured by reference: which techniques became checks,
     and how to pull an investigation/pentest playbook on demand.
5. **The completion bar is `PROTOCOL.md §7` + a GREEN ledger.** The gates below are
   the at-a-glance summary; the engine is what enforces them.

To **add a check** from a video / short / image / thread you send me, see
`MEDIA-INTAKE.md` — each is extracted, oracle-anchored, formalized into a registry
record, validated, and logged. Nothing you send is dropped.

## The core philosophy (read this every time)

### 1. Your own tests lie to you by default
The single biggest security-testing failure is **the author grading their own
homework**: you write the code, then write a test that asserts the code does what
you already believe it does. That test passes whether or not the code is *secure*
— it only proves the code is *consistent with your assumption*. Real security
tests are **falsifiable** and **adversarial**: each one is anchored to an external
oracle (an OWASP entry, an RFC clause, a CWE id) and tries to *break* the system,
not confirm it. See `security-testing-methodology.md`.

### 2. Every security control needs a documented failure mode
For each control, you must be able to answer: *"What happens when this fails — and
is failing OPEN or CLOSED the right call?"* An auth check fails closed (deny). A
rate limiter or an LLM guardrail usually fails open (allow + alert) so a bug in the
*defense* can't take down the *product*. Pick deliberately; never let it be an
accident. See the fail-open/closed framework in `secrets-and-ops.md`.

### 3. Security that's too expensive gets turned off
A control that doubles your per-request cost or adds a second of latency will be
disabled the first time it's inconvenient. Cheap-but-80%-effective beats
expensive-but-99%-that-gets-removed. Always cost the control (latency, $, ops
burden) and prefer the cheapest layer that meets the threat. Escalate to expensive
controls only when the threat model justifies it — and document the trigger.

### 4. Every new control ships with an off-switch
Any control that can block a legitimate user (lockout, guardrail, WAF rule) needs
an **env-flag kill switch** so it can be disabled in seconds during an incident
*without a code change or redeploy*. If you can't turn it off fast, you can't
turn it on safely.

### 5. The response itself is part of the attack surface
`403 Forbidden` vs `404 Not Found` on a resource you don't own *leaks the
resource's existence*. Differential responses are an oracle attackers enumerate:
in rough order of how cheaply they're exploited — **status code → error text →
body length → timing**. Equalize them in that priority order. Status/text/length
are easy and you should always match them ("indistinguishable from never-existed"
is the bar). **Timing is the hardest** to equalize and rarely worth chasing for
ordinary CRUD authz — a scoped DB query for a missing row vs an owned row can
differ by microseconds, and fully constant-time DB access is impractical. Reserve
timing-attack defense (constant-time compare, artificial delays) for the places it
genuinely matters: secret/token/HMAC comparison (use a constant-time compare — see
`hardening-playbook.md`), and auth flows where a measurable
user-exists-vs-not delta enables enumeration. Don't claim "timing-indistinguishable"
unless you've actually measured and equalized it.

## Gates — do not call something "secure" until all pass

> These gates are now encoded as records in `engine/registry.yaml` and enforced by
> the ledger (`sweep.py` exits non-zero while any is open). The authoritative,
> ordered completion bar is `PROTOCOL.md §7`; the list below is the at-a-glance summary.

- [ ] Every access-control path is tested with a **second identity** trying to
      reach the first's data (BOLA/IDOR), and the denial is **indistinguishable
      from "resource doesn't exist"** (same status, body, timing class).
- [ ] Every rate limit is tested by **rotating the spoofable identifier**
      (X-Forwarded-For, X-Real-IP) — the limit must hold on the *authenticated*
      identity, not the source IP alone.
- [ ] Every quota/balance debit is tested **concurrently** — the check and the
      debit are atomic (single guarded UPDATE), not check-then-act.
- [ ] Auth-failure throttling is tested at the **documented threshold** with
      *valid-shaped* credentials (so input validation doesn't mask the test).
- [ ] Every JWT *type* (access / 2FA-challenge / password-reset / email-verify) is
      tested as a `Bearer` on a protected route — only the access token is accepted,
      all others **401** (token-purpose confusion → 2FA/auth bypass; see
      `hardening-playbook.md §5b`).
- [ ] No secret format (key, token, hash, password) can appear in logs, alerts,
      error bodies, or LLM outputs — tested with planted secrets (CWE-532).
- [ ] Every security control has a **kill switch** and a **documented
      fail-open/closed** decision.
- [ ] Security tests **pass in a clean batch run**, not just in isolation — a
      "passes alone, fails in CI" result is a test-isolation defect that hides
      real regressions (see Anti-pattern #13).
- [ ] Secrets live in the platform's secret store, never in the repo, never in
      client-visible URLs/params, never echoed back to the caller.

## What this skill deliberately does NOT re-explain

The generic floor — TLS everywhere, bcrypt/argon2 for passwords, parameterized
queries, CSRF tokens, the OWASP Top 10 definitions, "validate all input". Assume
those are done. This skill is about everything *after* that.

## Apex over the floor (how this relates to the other security skills)

Bedrock is the **apex** security system; the basic skills are its **Tier-0 floor**:
- `owasp-top-10` — the A01–A10 definitions + baseline mitigations.
- `security-guidance` — generic input-validation / secrets / common-vuln guidance.
- `security-hardening` — starter FastAPI snippets (rate limit, Pydantic, CORS/headers).

The engine still **confirms** the floor (the `FLOOR-*` records) so "assumed" never
silently means "absent". Where a floor skill teaches a pattern this skill considers
unsafe, **bedrock wins and the floor is corrected** — specifically the naive
in-memory rate limiter keyed on `request.client.host` (see `PATTERN-001` /
`hardening-playbook.md §3`) and the `403`-on-others'-objects existence leak (see
`PATTERN-002` / `hardening-playbook.md §1`). Those floor skills now carry a pointer
back here so the contradiction can't mislead a future pass.
