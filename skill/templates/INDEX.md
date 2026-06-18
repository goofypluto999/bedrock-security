# Proof Templates — coverage map

Runnable, oracle-anchored adversarial-test templates per stack. Copy the template
for an OPEN check, wire it to the real routes/models from the frame (Stage 0), and
run it until green. Each is a *falsifiable* test that tries to break the control.

**Status legend:** `✓` authored (seeded) · `QUEUED` planned, not yet written ·
`—` not a meaningful standalone proof for that stack.

The runner reads these paths from `engine/registry.yaml` and flags any `QUEUED` one
as "QUEUED (not yet written)" in the ledger — so a missing template is **visible**,
never a silent gap. Authoring a queued template is the same pattern as the seeded
ones; or send a relevant clip and I'll develop it (see `../MEDIA-INTAKE.md`).

| Check | python-fastapi | typescript-node | supabase-postgres |
|---|---|---|---|
| **BOLA-001** object authz | ✓ `test_bola.py` | ✓ `bola.test.ts` | ✓ `bola_rls.sql` |
| **RACE-001** quota race | ✓ `test_quota_race.py` | QUEUED `quota_race.test.ts` | ✓ `atomic_debit.sql` |
| **JWT-002** token-purpose / 2FA bypass | ✓ `test_token_purpose.py` | QUEUED `token_purpose.test.ts` | — |
| **BFLA-001** function authz | QUEUED `test_bfla.py` | QUEUED `bfla.test.ts` | — |
| **MASS-001** mass assignment | QUEUED `test_mass_assignment.py` | QUEUED `mass_assignment.test.ts` | — |
| **RATE-001** rate-limit XFF | QUEUED `test_rate_limit_xff.py` | QUEUED `rate_limit_xff.test.ts` | — |
| **LOCK-001** account lockout | QUEUED `test_lockout.py` | QUEUED `lockout.test.ts` | — |
| **JWT-001** JWT hardening | QUEUED `test_jwt_hardening.py` | QUEUED `jwt_hardening.test.ts` | — |
| **INJ-001** injection | QUEUED `test_injection.py` | QUEUED `injection.test.ts` | QUEUED `injection_probe.sql` |
| **TENANT-DEL-001** cascade safety | QUEUED `test_tenant_deletion.py` | — | QUEUED `cascade_safety.sql` |
| **SSRF-001** SSRF | QUEUED `test_ssrf.py` | QUEUED `ssrf.test.ts` | — |
| **WEBHOOK-001** webhook verify | QUEUED `test_webhook.py` | QUEUED `webhook.test.ts` | — |
| **IDEM-001** idempotency | QUEUED `test_idempotency.py` | QUEUED `idempotency.test.ts` | — |
| **TIMING-001** constant-time compare | QUEUED `test_timing_safe.py` | QUEUED `timing_safe.test.ts` | — |
| **SIZE-001** size/DoS limits | QUEUED `test_size_limits.py` | QUEUED `size_limits.test.ts` | — |
| **LLM-INJ-001** prompt injection | QUEUED `test_prompt_injection.py` | QUEUED `prompt_injection.test.ts` | — |
| **LLM-OUT-001** output scrub | QUEUED `test_output_scrub.py` | QUEUED `output_scrub.test.ts` | — |
| **AUDIT-001** audit append-only | — | — | QUEUED `audit_append_only.sql` |

Seeded so far: **7 templates** across all 3 stacks (BOLA ×3, RACE ×2, JWT-002 ×1,
plus the `python-fastapi/conftest.py` harness that encodes the test-isolation
discipline). The seeds cover the marquee/highest-severity checks and establish the
pattern every QUEUED one follows.

## Stack notes
- **python-fastapi** — pytest + httpx; shared fixtures + isolation discipline live in
  `conftest.py` (StaticPool DB, autouse store resets, two identities A/B).
- **typescript-node** — vitest + supertest; works for Express / Fastify / Next API routes.
- **supabase-postgres** — psql/SQL editor scripts that assert via `raise exception`;
  run against TEST/STAGING only (never prod — reads stay read-only on live data).

## Additions 2026-06-18 (reels + ACS corpus) — template status

| Check | python-fastapi | typescript-node | supabase-postgres |
|---|---|---|---|
| **AUTHN-REQUIRED-001** unauth-access ("Postman test") | ✓ `test_authn_required.py` | QUEUED `authn_required.test.ts` | — |
| **SUPABASE-RLS-001** RLS on all tables | — | — | ✓ `bola_rls.sql` (reused) |
| **AUTHZ-SERVER-001** server-side authz | — | QUEUED `server_authz.test.ts` | — |
| **CLIENT-ENV-001** client-exposed secret | — | QUEUED `client_env_exposure.test.ts` | — |
| **AUTH-STORAGE-001** token in localStorage | — | QUEUED `auth_storage.test.ts` | — |
| **PWPOLICY-001** password + HIBP | QUEUED `test_password_policy.py` | — | — |
| **TOKEN-ROTATE-001** refresh rotation | QUEUED `test_token_rotation.py` | — | — |
| **OAUTH-001** OAuth2/OIDC | QUEUED `test_oauth.py` | — | — |
| **XXE-001** | QUEUED `test_xxe.py` | — | — |
| **SSTI-001** | QUEUED `test_ssti.py` | — | — |
| **NOSQLI-001** | — | QUEUED `nosql_injection.test.ts` | — |
| **PATHTRAV-001** | QUEUED `test_path_traversal.py` | — | — |
| **REDIRECT-001** | QUEUED `test_open_redirect.py` | — | — |
| **PAGINATION-001** | QUEUED `test_pagination.py` | — | — |
| **EXCESSDATA / ERRORLEAK / HOSTHDR / CLICKJACK / WEBSOCKET / APIINV / SOURCEMAP / COOKIE-FLAGS / ACCT-VERIFY / CISEC** | static-scan or decision (no test template needed) or QUEUED | — | — |

Registry now: **76 checks**. The runner flags every `QUEUED` template in the ledger
as "QUEUED (not yet written)" — gaps stay visible, never silent. Static-scan and
decision checks are proven by the runner / a documented decision and need no template.
