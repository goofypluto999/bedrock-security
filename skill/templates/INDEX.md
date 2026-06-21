# Proof Templates — coverage map

Runnable, oracle-anchored adversarial-test templates per stack. Copy the template for a
check, wire it to the real routes/models from the frame (Stage 0), and run it until green.
Each is a *falsifiable* test that actively tries to break the control — never happy-path.
Phase B: the pytest `assets` fixture auto-wires `user_a`/`user_b` from `.bedrock/assets.json`
+ `$BEDROCK_TOKEN_A/B`; `seed_bedrock.sql` + `_fixtures/bedrock-stripe-fixture.json` seed the suite.

**Status:** `✓` authored · `QUEUED` declared but not yet written · `—` not a meaningful
standalone proof for that stack. The runner reads these paths from `engine/registry.yaml`
and flags any `QUEUED` one in the ledger, so a gap is always visible, never silent.

**All 64 of 64 declared templates are authored** (42 checks carry at least
one proof template). Static-scan and decision checks are proven by the runner or a documented
decision and need no template.

| Check | python-fastapi | typescript-node | supabase-postgres |
|---|---|---|---|
| **BOLA-001** | ✓ `test_bola.py` | ✓ `bola.test.ts` | ✓ `bola_rls.sql` |
| **BFLA-001** | ✓ `test_bfla.py` | ✓ `bfla.test.ts` | — |
| **MASS-001** | ✓ `test_mass_assignment.py` | ✓ `mass_assignment.test.ts` | — |
| **RATE-001** | ✓ `test_rate_limit_xff.py` | ✓ `rate_limit_xff.test.ts` | — |
| **LOCK-001** | ✓ `test_lockout.py` | ✓ `lockout.test.ts` | — |
| **RACE-001** | ✓ `test_quota_race.py` | ✓ `quota_race.test.ts` | ✓ `atomic_debit.sql` |
| **JWT-001** | ✓ `test_jwt_hardening.py` | ✓ `jwt_hardening.test.ts` | — |
| **JWT-002** | ✓ `test_token_purpose.py` | ✓ `token_purpose.test.ts` | — |
| **INJ-001** | ✓ `test_injection.py` | ✓ `injection.test.ts` | ✓ `injection_probe.sql` |
| **TENANT-DEL-001** | ✓ `test_tenant_deletion.py` | — | ✓ `cascade_safety.sql` |
| **SSRF-001** | ✓ `test_ssrf.py` | ✓ `ssrf.test.ts` | — |
| **WEBHOOK-001** | ✓ `test_webhook.py` | ✓ `webhook.test.ts` | — |
| **IDEM-001** | ✓ `test_idempotency.py` | ✓ `idempotency.test.ts` | — |
| **TIMING-001** | ✓ `test_timing_safe.py` | ✓ `timing_safe.test.ts` | — |
| **SIZE-001** | ✓ `test_size_limits.py` | ✓ `size_limits.test.ts` | — |
| **LLM-INJ-001** | ✓ `test_prompt_injection.py` | ✓ `prompt_injection.test.ts` | — |
| **LLM-OUT-001** | ✓ `test_output_scrub.py` | ✓ `output_scrub.test.ts` | — |
| **AUDIT-001** | — | — | ✓ `audit_append_only.sql` |
| **CLIENT-ENV-001** | — | ✓ `client_env_exposure.test.ts` | — |
| **AUTH-STORAGE-001** | — | ✓ `auth_storage.test.ts` | — |
| **AUTHZ-SERVER-001** | — | ✓ `server_authz.test.ts` | — |
| **AUTHN-REQUIRED-001** | ✓ `test_authn_required.py` | ✓ `authn_required.test.ts` | — |
| **SUPABASE-RLS-001** | — | — | ✓ `bola_rls.sql` |
| **PATHTRAV-001** | ✓ `test_path_traversal.py` | — | — |
| **REDIRECT-001** | ✓ `test_open_redirect.py` | — | — |
| **PWPOLICY-001** | ✓ `test_password_policy.py` | — | — |
| **TOKEN-ROTATE-001** | ✓ `test_token_rotation.py` | — | — |
| **OAUTH-001** | ✓ `test_oauth.py` | — | — |
| **XXE-001** | ✓ `test_xxe.py` | — | — |
| **SSTI-001** | ✓ `test_ssti.py` | — | — |
| **NOSQLI-001** | — | ✓ `nosql_injection.test.ts` | — |
| **PAGINATION-001** | ✓ `test_pagination.py` | — | — |
| **ERRORLEAK-001** | ✓ `test_error_sanitization.py` | — | — |
| **SBA-ANON-001** | — | — | ✓ `anon_rls_audit.sql` |
| **NEXT-RSC-001** | — | ✓ `rsc_leak.test.ts` | — |
| **EDGE-MW-001** | — | ✓ `edge_mw_bypass.test.ts` | — |
| **BILLING-WEBHOOK-001** | — | ✓ `billing_webhook.test.ts` | — |
| **ENTITLEMENT-001** | ✓ `test_entitlement.py` | — | — |
| **CACHE-TENANT-001** | — | ✓ `cache_tenant.test.ts` | — |
| **ADMIN-001** | ✓ `test_bfla.py` | ✓ `bfla.test.ts` | — |
| **LLM-BLIND-001** | ✓ `test_llm_blind_ssrf.py` | — | — |
| **RAG-TENANT-001** | ✓ `test_rag_tenant.py` | — | — |

## Stack notes
- **python-fastapi** — pytest + httpx; shared fixtures + the test-isolation discipline live in
  `conftest.py` (StaticPool DB, autouse store resets, two identities A/B, the Phase-B `assets` fixture).
- **typescript-node** — vitest + supertest; works for Express / Fastify / Next API routes.
- **supabase-postgres** — psql / SQL-editor scripts that assert via `raise exception`, wrapped in
  `begin; … rollback;`; run against TEST/STAGING only. `seed_bedrock.sql` seeds tenant A/B + rows.

## Adding more
A new adversarial check ships with at least one stack template (or is flagged QUEUED here and in
the ledger — never silently template-less). To turn a video/short/image into a check + template,
see `../MEDIA-INTAKE.md`.
