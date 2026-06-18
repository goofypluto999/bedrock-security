# Security Testing Methodology — proving security instead of assuming it

> The reference for *how to test* security. Generic test-writing confirms code
> works as the author intended; security testing must try to prove the author
> wrong. This doc is the difference.

## 1. The grade-your-own-homework trap (the #1 failure)

When the same mind writes the implementation and the test, the test encodes the
*author's assumptions*, not the *security property*. It passes because the code
matches what the author believed — which is exactly the thing that's wrong when
there's a vulnerability.

Symptoms:
- Tests assert the happy path returns the right shape, never that a *wrong actor*
  is denied.
- "Negative" tests use inputs the author already handles, never the input class
  the author forgot.
- Coverage is high; adversarial coverage is zero.

The fix — **adversarial, oracle-anchored, isolation-authored tests:**

### Oracle-anchoring
Every security test cites an *external* authority for what "correct" means:
- An **OWASP** entry (e.g. API1:2023 BOLA, A03:2021 Injection, LLM01 Prompt Injection)
- An **RFC** clause (e.g. RFC 8725 JWT BCP, RFC 6585 §4 Retry-After, RFC 7231 §6.5.2 402)
- A **CWE** id (e.g. CWE-532 info-in-logs, CWE-89 SQLi, CWE-79 XSS, CWE-639 IDOR)

If a test can't name the authority it's enforcing, it's probably enforcing your
assumption. Write the citation in the test docstring. It forces you to look up
what the standard *actually requires* rather than what you remember.

### Isolation authorship (the strongest version)
Have the security tests written by an actor that **cannot see the implementation
reasoning** — a separate session/agent/person who is given:
- the public interface (routes, request/response schemas),
- the threat model (who the attackers are, what they want),
- the oracles (OWASP/RFC/CWE list),
- and explicitly NOT the implementation's internal justifications.

This "firewall" prevents the test author from absorbing the implementer's
assumptions. They write tests against the *contract and the standard*, then run
them against the real system. Tests that fail reveal either a real bug or a real
spec gap — both valuable. (This is the single highest-leverage practice in this
whole skill.)

## 2. Falsifiable specifications

A good security spec is a statement that can be *proven false* by a test. Bad:
"the endpoint is secure". Good: "a request for resource R by an identity that
does not own R returns a response byte-indistinguishable from a request for a
resource that never existed (same status, same body, same timing class)."

Write each security requirement as a falsifiable sentence first, THEN write the
test that tries to falsify it. If you can't phrase it falsifiably, you don't yet
understand the property well enough to test it.

## 3. The triage taxonomy (when a security test fails, what is it?)

Not every red test is a product bug. Classify before fixing — fixing the wrong
class wastes hours and can mask real defects.

- **Class 1 — Real product vulnerability.** The system genuinely lets an attacker
  do the bad thing. Fix the code. (Highest priority.)
- **Class 2 — Real but lower-severity / defense-in-depth gap.** Exploitable only
  under unusual conditions, or mitigated elsewhere. Fix or consciously accept +
  document.
- **Class 3 — Environment-only failure.** The bug only reproduces under a test
  shortcut (e.g. SQLite-only behavior that Postgres doesn't have, no real
  concurrency under a single-threaded test client). The *contract* is fine; the
  *test harness* can't express it. Document, don't "fix" by weakening the code.
- **Class 4 — Invalid spec.** The test asserts something the system was never
  meant to do, or encodes a misunderstanding of the engine/standard. Fix the
  test, not the code. (Common when the spec author guessed at internal behavior.)
- **Class 5 — Platform/infra limitation.** The contract is Postgres-only,
  Redis-only, multi-worker-only, etc., and can't be exercised in the test
  environment at all. Mark explicitly; verify in staging instead.

Record the class for every failure in a triage log. "12 failing tests" is
meaningless; "1 Class-1, 3 Class-3, 8 Class-4" is an action plan.

## 4. Anti-pattern #13 — test-order / state-leak (the silent regression-hider)

> Named here as #13 because it's the one nobody documents and everybody hits.

**Symptom:** a test passes when run alone but fails in the full suite ("passes in
isolation, fails in batch"), or vice versa. Test *order* changes the result.

**Why it's dangerous for security specifically:** when your security tests are
order-dependent, a CI run that goes green tells you nothing — the security
assertion may have been satisfied by leftover state from a previous test, not by
the code under test. It also means a *real* security regression can hide behind a
flapping unrelated test.

**Root causes (in rough order of frequency):**

1. **Shared in-memory DB across connections.** `sqlite+aiosqlite://` (and similar)
   create a *separate* in-memory database per connection. Tables created on
   connection A are invisible to connection B → "no such table" in batch.
   *Fix:* pin a single connection for the whole test session
   (SQLAlchemy `poolclass=StaticPool` + `connect_args={"check_same_thread": False}`).

2. **Module-global capture vs late binding.** `from db import session` captures
   the object *at import time*. If tests later monkeypatch `db.session`, the
   module that did `from db import session` never sees the patch — it still
   writes to the original (often a real/empty DB). *Fix:* in code that must be
   test-rebindable, use `import db` + `db.session()` at call time (late binding),
   not `from db import session` at module top.

3. **Last-importer-wins dependency overrides.** Test frameworks import every test
   module before running any test. If each test file sets a global override
   (e.g. a DI container's dependency map) at module load, the *last file imported*
   wins for *every* test. *Fix:* set overrides in an autouse per-test fixture that
   re-pins before each test, keyed on the *original* function reference (the one
   the routes actually captured), not a possibly-mutated module attribute.

4. **Process-global counters/caches/rate-limit storage** that persist across
   tests. *Fix:* an autouse fixture that resets the store (rate-limiter storage,
   lockout dict, LRU caches) before and after each test.

5. **Module-level RNG seeding leaking across tests.** A test that calls
   `random.seed(42)` changes the global RNG for every later test. Statistical or
   determinism assertions then flip depending on order. *Fix:* seed inside the
   test that needs it, or pass an explicit RNG/seed into the code under test
   rather than relying on the global module RNG.

**The diagnostic:** run the failing test ALONE. If it passes alone but fails in
batch → it's Anti-pattern #13 (test infra), NOT a product bug. Do not "fix" the
product to satisfy a state-leak; fix the isolation.

## 5. What to actually test (the security test matrix)

For any app with auth + multi-tenancy + quotas, the non-negotiable test set:

| Property | The adversarial test | Oracle |
|---|---|---|
| Object authz (BOLA/IDOR) | Identity B requests A's object by id → must be **404, indistinguishable from non-existent** | OWASP API1:2023, CWE-639 |
| Function authz (BFLA) | Lower-role token hits an admin/owner-only route → 403 | OWASP API5:2023 |
| Mass assignment | POST privileged fields (role, plan, is_admin, tenant_id) → server ignores them; re-fetch proves unchanged | OWASP API6:2023 |
| Rate limit (per-identity) | Send N+1 while **rotating X-Forwarded-For/X-Real-IP** → still 429 on the authenticated identity | OWASP API4:2023 |
| Anti-brute-force | N failed logins on one email **from many IPs** → throttled by email, not just IP | OWASP API4:2023, ASVS V2.2.1 |
| Quota race | Fire the (N+1)th quota-consuming request **concurrently** → exactly N succeed, never N+1 | (logic; no single CWE) |
| Secret leakage | Plant a secret in an input that bubbles into logs/errors/emails/LLM output → assert it's redacted | CWE-532 |
| Token hardening | alg=none, alg-confusion (RS→HS), missing `exp`, expired, tampered sig → all rejected | RFC 8725 |
| Injection (SQL/XSS/cmd) | Inject in every string field → parameterized/escaped, never 500 with a DB error, never reflected as executable | A03:2021, CWE-89/79/78 |
| Cross-tenant deletion | A deletes their account → B's row counts unchanged (no cascade across tenant boundary) | OWASP API1, GDPR Art.17 |
| Prompt injection (if LLM) | Injection payload in any user text that reaches an LLM → blocked or neutralized before dispatch | OWASP LLM01:2025 |

## 6. CI discipline for security tests

- Security tests run on **every** PR, not nightly-only.
- A security test failing **blocks merge** — it is never "flaky, re-run it" without
  a triage-class assigned first.
- Run the suite in a **fixed, then randomized** order in CI. If randomized order
  changes results, you have Anti-pattern #13 → fix isolation before trusting any
  green run.
- Keep a **triage log** in the repo (`tests/security/TRIAGE.md`) recording every
  historical failure, its class, and resolution. Future-you will re-hit the same
  Class-3/4/5 confusions otherwise.

## 7. The completion bar

Do not report "security tested" until:
- the adversarial matrix above is implemented and green **in a clean batch run**,
- every red was triaged to a class and either fixed (Class 1/2) or documented
  (Class 3/4/5),
- the suite is order-independent (passes randomized),
- and the oracles are cited in each test so a reviewer can verify *correctness*,
  not just *passing*.

## 8. Running a full audit — multi-lens, multi-agent, with cross-checking

A one-pass review misses things. A real internal audit layers *independent* lenses
so each catches what the others don't. The proven structure:

1. **Frame the surface first.** Inventory every endpoint, auth mode, external call,
   secret, and data store before going deep. You can't audit what you haven't
   enumerated.
2. **Pick a rubric** (this skill's gates + control matrix) and score against it —
   don't free-associate.
3. **Run multiple lenses in sequence:** a checklist pass, a controls pass, an
   unsafe-pattern pass. They overlap deliberately; overlap is how you catch the
   thing one lens is blind to.
4. **Parallelize by domain with fresh-context agents.** Split the audit into
   independent domains (authn/authz, rate-limit/secrets, LLM/input,
   SSRF/webhook/idempotency, test-coverage) and have a *separate* reviewer do each.
   Fresh context = no shared assumptions. Give each the relevant rubric section and
   the real code, demand file:line evidence per claim, and a severity per finding.
5. **Run a dedicated purpose-tracing pass.** The highest-value bugs (e.g. the
   token-purpose confusion in `hardening-playbook.md §5b`) are found by *tracing a
   property across the whole flow*, not by per-file review. Budget one pass that
   does nothing but follow auth/identity/trust across boundaries.
6. **Finish with an independent automated pass** (an AI security-review action or
   equivalent) and **cross-check** it against the human/agent findings — each tends
   to catch what the other misses. In the real audit this skill is built from, a
   HIGH-severity 2FA bypass was found *only* by the dedicated purpose-tracing
   automated pass; five other capable reviewers missed it. Use all the lenses.

**Cross-checking is mandatory, in both directions:**
- An agent that reports "control X is missing" may be reading **stale docs**, not
  the current code. **Verify every 'missing' claim against the live code** before
  acting — one audit agent flagged four controls as "unimplemented" purely from
  out-of-date triage notes; all four were actually shipped and live.
- Conversely, an agent that reports "✅ present" should cite the file:line so you
  can confirm it's wired on *every* relevant route, not just one.

## 9. Stale security docs are an audit hazard

Triage logs, test docstrings, and design notes describing controls as "TODO /
Class-1 / unimplemented" **rot the moment the control ships**. Then:
- a future auditor (human or agent) reads the stale note and reports a *fixed*
  control as a live vulnerability (false positive, wasted remediation), or
- a green-looking test that's documented as an "expected-FAIL" gets "fixed" to pass
  without fixing the product, silently destroying the only red flag.

**Rule:** when you fix a control, update or delete the doc that called it broken in
the *same change*. A test whose docstring says "this is expected to fail because
the control doesn't exist" must be rewritten the moment the control exists — the
docstring is part of the test's correctness.

## 10. Where security tests sit (the pyramid) + stub vs mock

> Folded in from two testing-methodology reels (intake 2026-06-18). Not security
> controls themselves, but they shape HOW the adversarial suite is built.

**The test pyramid** — many cheap **unit** tests, fewer **integration**, very few
expensive **end-to-end**. Security tests live at all three levels, but the
highest-value adversarial ones (BOLA, token-purpose/2FA-bypass, quota race) are
**integration/e2e** — they cross the auth/identity/trust boundary that unit tests
mock away. Budget for them deliberately; "it's an expensive e2e" must never be the
reason the 2FA-bypass test (JWT-002) never gets written. Cheap unit checks (regex
ReDoS, scrubber patterns) at the base; the boundary-crossing proofs at the top.

**Stub vs mock (and why it matters for security):**
- A **stub** supplies canned data so the code runs (a fake user store returning a
  seeded user). Use stubs to *set up* the adversarial scenario (identity A owns
  object X; identity B exists).
- A **mock** asserts an *interaction happened*: the rate-limiter was consulted, the
  scrubber was invoked, the LLM was **not** dispatched on a blocked input. Use mocks
  to *prove a control fired* — e.g. assert `scan_input` was called and raised
  **before** `model.dispatch`, which proves the guard runs pre-dispatch (LLM-INJ-001),
  an ordering a stub can't verify.
- **The trap:** a mock that asserts "the code did what I assume" is grade-your-own-
  homework (§1), not proof the security property holds. Pair interaction-mocks with
  **real adversarial inputs** and an external oracle. The isolation discipline (§4)
  keeps these multi-level tests honest in a batch run.
