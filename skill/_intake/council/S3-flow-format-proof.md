# S3 — Flow, Format, Protocol & Proof/UX
## Squad agent specification for bedrock-security elevation

> Primary source: `03-synthesis.md` (the council's consolidated build contract).
> Scope: `.bedrock/assets.json` schema, fixture-seeding contract, enriched `ledger.json`
> evidence schema, `server.py` DAG-progress console model, proof→regression integration,
> and the clean-floor guarantee.

---

## 1. `.bedrock/assets.json` — Full JSON Schema

The FRAME stage (Stage 1) writes this file. Every adversarial template in `templates/`
reads it instead of using hardcoded placeholders. `sweep.py` refuses to execute
DYNAMIC-ADVERSARIAL checks until this file exists and passes schema validation.

### 1a. Canonical Schema (JSON Schema draft-07)

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "$id": "bedrock-assets-v1",
  "description": "Attack surface map produced by Stage 1 FRAME; consumed by adversarial templates.",
  "type": "object",
  "required": ["schema_version", "generated_at", "target", "stack", "routes", "roles",
               "token_types", "tenant_resources", "external_fetches", "webhooks",
               "llm_surfaces", "datastores", "secrets", "deploy_targets"],
  "additionalProperties": false,
  "properties": {

    "schema_version": { "type": "string", "enum": ["1"] },
    "generated_at":   { "type": "string", "format": "date-time" },

    "target": {
      "type": "object",
      "required": ["base_url", "environment"],
      "properties": {
        "base_url":    { "type": "string", "description": "e.g. https://staging.my-saas.com" },
        "environment": { "type": "string", "enum": ["pre-commit", "ci", "preview", "staging", "prod"] },
        "repo_root":   { "type": "string", "description": "Absolute local path" }
      }
    },

    "stack": {
      "type": "object",
      "description": "Detected framework/runtime — drives template selection (INV-008).",
      "properties": {
        "language":     { "type": "string", "examples": ["python", "typescript", "javascript"] },
        "framework":    { "type": "string", "examples": ["fastapi", "nextjs", "express", "fastify"] },
        "runtime":      { "type": "string", "examples": ["node", "python", "edge", "bun"] },
        "db":           { "type": "string", "examples": ["postgres", "supabase", "mysql", "mongo"] },
        "auth_provider":{ "type": "string", "examples": ["supabase", "clerk", "auth0", "custom"] }
      }
    },

    "routes": {
      "type": "array",
      "description": "Every route/endpoint identified by INV-001.",
      "items": {
        "type": "object",
        "required": ["path", "methods", "auth_required"],
        "properties": {
          "path":         { "type": "string", "description": "e.g. /api/invoices/{id}" },
          "methods":      { "type": "array", "items": { "type": "string" } },
          "auth_required":{ "type": "boolean" },
          "roles_allowed":{ "type": "array", "items": { "type": "string" },
                            "description": "Empty = any authenticated; null = not checked yet" },
          "has_param_id": { "type": "boolean", "description": "Path has a resource-id parameter" },
          "data_class":   { "type": "string", "enum": ["public", "internal", "tenant", "pii", "secret", "unknown"],
                            "description": "Coarse classification of the data served" },
          "source_file":  { "type": "string", "description": "file:line where this route is defined" },
          "notes":        { "type": "string" }
        }
      }
    },

    "roles": {
      "type": "array",
      "description": "All auth roles/scopes discovered by INV-001 + INV-002.",
      "items": {
        "type": "object",
        "required": ["name"],
        "properties": {
          "name":        { "type": "string", "examples": ["owner", "member", "admin", "support", "anonymous"] },
          "token_env":   { "type": "string", "description": "Env var holding a test token for this role" },
          "privileged":  { "type": "boolean", "description": "True = admin/support/billing-owner" },
          "test_created":{ "type": "boolean", "description": "Whether seed_bedrock.sql created a test account" }
        }
      }
    },

    "token_types": {
      "type": "array",
      "description": "Every JWT/token type minted by this service (INV-002). Drives JWT-002.",
      "items": {
        "type": "object",
        "required": ["name", "purpose"],
        "properties": {
          "name":        { "type": "string", "examples": ["access", "refresh", "2fa_challenge", "email_verify", "password_reset"] },
          "purpose":     { "type": "string" },
          "exp_seconds": { "type": "integer", "description": "Nominal lifetime in seconds" },
          "alg":         { "type": "string", "examples": ["RS256", "HS256", "ES256"] },
          "aud":         { "type": "string" },
          "iss":         { "type": "string" },
          "source_file": { "type": "string", "description": "Where this token type is minted (file:line)" }
        }
      }
    },

    "tenant_resources": {
      "type": "array",
      "description": "Tenant-scoped object types (INV-005). Drives BOLA-001, SUPABASE-RLS-001, TENANT-DEL-001.",
      "items": {
        "type": "object",
        "required": ["type", "table_or_collection", "owner_field"],
        "properties": {
          "type":                 { "type": "string", "description": "e.g. invoice, document, subscription" },
          "table_or_collection":  { "type": "string", "description": "Postgres table or collection name" },
          "owner_field":          { "type": "string", "description": "Column/field that holds the owning tenant/user id" },
          "route_pattern":        { "type": "string", "description": "API path that exposes this resource" },
          "rls_enabled":          { "type": ["boolean", "null"], "description": "null = not yet verified" },
          "test_object_a_id":     { "type": "string", "description": "Seeded id belonging to tenant A" },
          "test_object_b_id":     { "type": "string", "description": "Seeded id belonging to tenant B" },
          "data_class":           { "type": "string", "enum": ["public", "internal", "tenant", "pii", "secret", "unknown"] }
        }
      }
    },

    "external_fetches": {
      "type": "array",
      "description": "Server-side outbound HTTP calls inventoried by INV-003. Drives SSRF-001.",
      "items": {
        "type": "object",
        "required": ["source_file", "param_user_controlled"],
        "properties": {
          "source_file":         { "type": "string" },
          "url_pattern":         { "type": "string", "description": "Static URL or parameterized pattern" },
          "param_user_controlled":{ "type": "boolean" },
          "allowlist_enforced":  { "type": ["boolean", "null"] },
          "redirect_revalidated":{ "type": ["boolean", "null"] }
        }
      }
    },

    "webhooks": {
      "type": "array",
      "description": "Inbound webhook endpoints (INV-003). Drives WEBHOOK-001, BILLING-WEBHOOK-001.",
      "items": {
        "type": "object",
        "required": ["provider", "path"],
        "properties": {
          "provider":          { "type": "string", "examples": ["stripe", "github", "twilio", "custom"] },
          "path":              { "type": "string", "description": "Route that receives the webhook" },
          "secret_env":        { "type": "string", "description": "Env var holding the HMAC signing secret" },
          "raw_body_preserved":{ "type": ["boolean", "null"], "description": "Does handler read raw bytes before parsing?" },
          "replay_window_sec": { "type": ["integer", "null"], "description": "Timestamp replay window (null = not enforced)" },
          "idempotency_field": { "type": ["string", "null"], "description": "Field used for dedup, e.g. stripe event id" }
        }
      }
    },

    "llm_surfaces": {
      "type": "array",
      "description": "Every point where user-influenced text reaches a language model (INV-006). Drives LLM-INJ-001, LLM-OUT-001, LLM-BLIND-001, RAG-TENANT-001.",
      "items": {
        "type": "object",
        "required": ["surface_id", "model_provider", "user_input_reaches_prompt"],
        "properties": {
          "surface_id":               { "type": "string", "description": "Stable identifier, e.g. chat-endpoint" },
          "source_file":              { "type": "string" },
          "model_provider":           { "type": "string", "examples": ["anthropic", "openai", "google"] },
          "model_id":                 { "type": "string" },
          "user_input_reaches_prompt":{ "type": "boolean" },
          "tools_exposed":            { "type": "array", "items": { "type": "string" },
                                        "description": "Tool names callable by the model" },
          "tool_has_fetch_url":       { "type": "boolean", "description": "True = LLM-BLIND-001 applies" },
          "has_rag_retrieval":        { "type": "boolean", "description": "True = RAG-TENANT-001 applies" },
          "rag_tenant_filter_field":  { "type": ["string", "null"], "description": "Field used for tenant isolation in vector search" },
          "output_reaches_client":    { "type": "boolean" },
          "has_guardrail":            { "type": ["boolean", "null"] },
          "guardrail_fail_open":      { "type": ["boolean", "null"] },
          "kill_switch_env":          { "type": ["string", "null"] }
        }
      }
    },

    "datastores": {
      "type": "array",
      "description": "Every data store (INV-005). Drives SUPABASE-RLS-001, AUDIT-001, CACHE-TENANT-001, SEARCH-TENANT-001.",
      "items": {
        "type": "object",
        "required": ["type", "identifier"],
        "properties": {
          "type":            { "type": "string", "enum": ["postgres", "supabase", "mongo", "redis", "s3", "vector", "search", "other"] },
          "identifier":      { "type": "string", "description": "DB name, bucket name, index name, etc." },
          "supabase_project":{ "type": ["string", "null"], "description": "Supabase project ref if type=supabase" },
          "rls_policy_count":{ "type": ["integer", "null"], "description": "Number of RLS policies found; 0 = SBA-ANON-001 applies" },
          "tenant_scoped":   { "type": ["boolean", "null"], "description": "All queries include tenant filter?" },
          "audit_log_enabled":{ "type": ["boolean", "null"] },
          "cache_keys_tenant_scoped": { "type": ["boolean", "null"], "description": "For Redis/CDN: keys include tenant id?" }
        }
      }
    },

    "secrets": {
      "type": "array",
      "description": "Env var NAMES (never values) enumerated by INV-004. Drives SEC-LEAK-001, ENV-001/002, PATTERN-003.",
      "items": {
        "type": "object",
        "required": ["name"],
        "properties": {
          "name":           { "type": "string", "description": "Env var name, e.g. STRIPE_SECRET_KEY" },
          "exposed_client": { "type": "boolean", "description": "True if prefixed NEXT_PUBLIC_ or VITE_ etc." },
          "in_gitignore":   { "type": ["boolean", "null"] },
          "in_example_file":{ "type": "boolean", "description": "Appears in .env.example with no value?" },
          "sinks":          { "type": "array", "items": { "type": "string" },
                              "description": "file:line locations where this var is read/used" }
        }
      }
    },

    "deploy_targets": {
      "type": "array",
      "description": "Deployment targets confirmed by INV-007. Drives DEPLOY-GATE-001, SCOPE-001.",
      "items": {
        "type": "object",
        "required": ["platform", "confirmed_owned"],
        "properties": {
          "platform":       { "type": "string", "examples": ["vercel", "railway", "fly.io", "render", "aws", "gcp"] },
          "url":            { "type": "string" },
          "confirmed_owned":{ "type": "boolean" },
          "rollback_command":{ "type": ["string", "null"], "description": "e.g. vercel rollback <deploy-id>" },
          "smoke_command":  { "type": ["string", "null"], "description": "Command that verifies deployment health" }
        }
      }
    }

  }
}
```

### 1b. Concrete Example Row (the Marr Media archetype — Vercel + Supabase + Stripe)

```json
{
  "schema_version": "1",
  "generated_at": "2026-06-21T10:00:00Z",
  "target": {
    "base_url": "https://staging.my-saas.com",
    "environment": "staging",
    "repo_root": "/home/runner/work/my-saas"
  },
  "stack": {
    "language": "typescript",
    "framework": "nextjs",
    "runtime": "edge",
    "db": "supabase",
    "auth_provider": "supabase"
  },
  "routes": [
    {
      "path": "/api/invoices/{id}",
      "methods": ["GET", "PATCH"],
      "auth_required": true,
      "roles_allowed": ["owner", "member"],
      "has_param_id": true,
      "data_class": "tenant",
      "source_file": "app/api/invoices/[id]/route.ts:12"
    },
    {
      "path": "/api/admin/users",
      "methods": ["GET", "DELETE"],
      "auth_required": true,
      "roles_allowed": ["admin"],
      "has_param_id": false,
      "data_class": "pii",
      "source_file": "app/api/admin/users/route.ts:5"
    }
  ],
  "roles": [
    { "name": "owner",     "token_env": "TEST_TOKEN_OWNER",   "privileged": false, "test_created": true },
    { "name": "member",    "token_env": "TEST_TOKEN_MEMBER",  "privileged": false, "test_created": true },
    { "name": "admin",     "token_env": "TEST_TOKEN_ADMIN",   "privileged": true,  "test_created": true },
    { "name": "anonymous", "token_env": null,                 "privileged": false, "test_created": false }
  ],
  "token_types": [
    { "name": "access",         "purpose": "API authentication",    "exp_seconds": 3600,   "alg": "RS256", "source_file": "lib/auth.ts:88" },
    { "name": "email_verify",   "purpose": "Email link confirmation","exp_seconds": 86400,  "alg": "HS256", "source_file": "lib/auth.ts:144" },
    { "name": "password_reset", "purpose": "Password reset link",   "exp_seconds": 900,    "alg": "HS256", "source_file": "lib/auth.ts:201" }
  ],
  "tenant_resources": [
    {
      "type": "invoice",
      "table_or_collection": "invoices",
      "owner_field": "org_id",
      "route_pattern": "/api/invoices/{id}",
      "rls_enabled": null,
      "test_object_a_id": "inv_aaa111",
      "test_object_b_id": "inv_bbb222",
      "data_class": "tenant"
    }
  ],
  "webhooks": [
    {
      "provider": "stripe",
      "path": "/api/webhooks/stripe",
      "secret_env": "STRIPE_WH_SECRET",
      "raw_body_preserved": null,
      "replay_window_sec": null,
      "idempotency_field": "id"
    }
  ],
  "external_fetches": [],
  "llm_surfaces": [],
  "datastores": [
    {
      "type": "supabase",
      "identifier": "abydokymlxekgybzmjtl",
      "supabase_project": "abydokymlxekgybzmjtl",
      "rls_policy_count": null,
      "tenant_scoped": null,
      "audit_log_enabled": null,
      "cache_keys_tenant_scoped": null
    }
  ],
  "secrets": [
    { "name": "STRIPE_SECRET_KEY",       "exposed_client": false, "in_gitignore": true, "in_example_file": true, "sinks": ["lib/stripe.ts:4"] },
    { "name": "NEXT_PUBLIC_SUPABASE_URL", "exposed_client": true,  "in_gitignore": false, "in_example_file": true, "sinks": ["lib/supabase/client.ts:2"] }
  ],
  "deploy_targets": [
    {
      "platform": "vercel",
      "url": "https://staging.my-saas.com",
      "confirmed_owned": true,
      "rollback_command": "vercel rollback",
      "smoke_command": "curl -f https://staging.my-saas.com/api/health"
    }
  ]
}
```

### 1c. How FRAME produces `assets.json`

Stage 1 INV checks each write their section via a shared `AssetWriter` in `sweep.py`:

```python
# engine/assets.py  (new module)
import json, pathlib, datetime

class AssetWriter:
    def __init__(self, out_dir: pathlib.Path):
        self._path = out_dir / "assets.json"
        self._data = {
            "schema_version": "1",
            "generated_at": datetime.datetime.utcnow().isoformat() + "Z",
            "target": {}, "stack": {}, "routes": [], "roles": [],
            "token_types": [], "tenant_resources": [], "external_fetches": [],
            "webhooks": [], "llm_surfaces": [], "datastores": [],
            "secrets": [], "deploy_targets": []
        }

    def patch(self, section: str, value):
        """For scalar sections (target, stack). Merges dict."""
        if isinstance(value, dict):
            self._data[section].update(value)
        else:
            self._data[section] = value

    def append(self, section: str, item: dict):
        """For array sections (routes, roles, etc.)."""
        self._data[section].append(item)

    def flush(self):
        self._path.write_text(json.dumps(self._data, indent=2))

    @classmethod
    def load(cls, out_dir: pathlib.Path) -> dict:
        """Templates call this to read assets at test time."""
        path = out_dir / "assets.json"
        if not path.exists():
            raise FileNotFoundError(f"assets.json not found at {path} — run sweep.py first")
        return json.loads(path.read_text())
```

All `INV-*` probe implementations call `writer.patch(...)` or `writer.append(...)`.
The file is flushed to disk after INV-008 completes. Downstream checks in Stages 2–6
load it via `AssetWriter.load(out_dir)`.

Templates use it like:

```python
# templates/typescript-node/bola.test.ts (excerpt)
import assets from "../../.bedrock/assets.json";

const tenantResource = assets.tenant_resources[0];   // first tenant-scoped type
const BASE_URL = assets.target.base_url;
const TOKEN_A  = process.env[assets.roles.find(r => r.name === "owner")!.token_env!];
const TOKEN_B  = process.env[assets.roles.find(r => r.name === "member")!.token_env!];
const OBJ_A_ID = tenantResource.test_object_a_id;
const OBJ_B_ID = tenantResource.test_object_b_id;
```

---

## 2. Fixture-Seeding Contract

The DYNAMIC-ADVERSARIAL stage requires real identities and real rows. Two fixture
vehicles: SQL for Supabase/Postgres, Stripe CLI for billing tests. Both are
rollback-wrapped and leave no permanent test state.

### 2a. `seed_bedrock.sql` — Supabase / Postgres fixture

Location: `templates/supabase-postgres/seed_bedrock.sql`

Design contract:
- Wrapped in `BEGIN; ... ROLLBACK;` — safe to run against any environment including
  production-equivalent staging as long as the connection is committed only at the test
  harness's discretion.
- The sweeper runs it with `ROLLBACK` by default. A human can swap to `COMMIT` manually
  to leave persistent seed data for iterative manual testing.
- UUIDs are fixed (not `gen_random_uuid()`) so `assets.json` can reference them literally.
- `ON CONFLICT DO NOTHING` — idempotent, safe to re-run.
- Covers exactly what the adversarial suite needs: two tenants, one object per tenant,
  two users, one admin user, one quota counter, one billing subscription row.

```sql
-- =============================================================
-- seed_bedrock.sql — Bedrock security test fixture
-- Run: psql $DATABASE_URL -f seed_bedrock.sql
-- All changes are rolled back by default.
-- To commit for iterative testing, replace ROLLBACK with COMMIT.
-- =============================================================
BEGIN;

-- -------------------------------------------------------------
-- ORGANISATIONS / TENANTS
-- Two distinct tenants. All adversarial tests isolate across these.
-- -------------------------------------------------------------
INSERT INTO organisations (id, name, plan, created_at)
VALUES
  ('00000000-0000-0000-0000-000000000001', 'Bedrock Tenant A', 'pro',  NOW()),
  ('00000000-0000-0000-0000-000000000002', 'Bedrock Tenant B', 'free', NOW())
ON CONFLICT (id) DO NOTHING;

-- -------------------------------------------------------------
-- USERS
-- owner-A and member-B are the primary BOLA/BFLA identities.
-- admin-A is the privileged account (BFLA-001, ADMIN-001).
-- Passwords are bcrypt of 'bedrock-test-pw-A' / 'bedrock-test-pw-B'.
-- Test tokens are supplied via env vars (TEST_TOKEN_OWNER, TEST_TOKEN_MEMBER, TEST_TOKEN_ADMIN).
-- -------------------------------------------------------------
INSERT INTO users (id, email, org_id, role, password_hash, created_at)
VALUES
  ('00000000-0000-0000-0001-000000000001', 'owner-a@bedrock.test',  '00000000-0000-0000-0000-000000000001', 'owner',  '$2b$12$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', NOW()),
  ('00000000-0000-0000-0001-000000000002', 'member-b@bedrock.test', '00000000-0000-0000-0000-000000000002', 'member', '$2b$12$BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB', NOW()),
  ('00000000-0000-0000-0001-000000000003', 'admin-a@bedrock.test',  '00000000-0000-0000-0000-000000000001', 'admin',  '$2b$12$CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC', NOW())
ON CONFLICT (id) DO NOTHING;

-- -------------------------------------------------------------
-- TENANT RESOURCES (one per tenant; type = whatever INV-005 found)
-- The actual table name is read from assets.json at test time.
-- This section is a template; sweep.py substitutes the real table name.
-- For the canonical example, table = 'invoices'.
-- -------------------------------------------------------------
-- BEDROCK_RESOURCE_TABLE_PLACEHOLDER_START
INSERT INTO invoices (id, org_id, amount_cents, status, created_at)
VALUES
  ('inv_aaa111aaa111aaa111aaa111aaa11100', '00000000-0000-0000-0000-000000000001', 9900, 'open', NOW()),
  ('inv_bbb222bbb222bbb222bbb222bbb22200', '00000000-0000-0000-0000-000000000002', 4900, 'open', NOW())
ON CONFLICT (id) DO NOTHING;
-- BEDROCK_RESOURCE_TABLE_PLACEHOLDER_END

-- -------------------------------------------------------------
-- QUOTA / BALANCE (for RACE-001 atomicity test)
-- Tenant A gets a balance of 100 units; the race test will
-- attempt to over-debit it concurrently.
-- -------------------------------------------------------------
INSERT INTO quota_ledger (id, org_id, balance, updated_at)
VALUES
  ('00000000-0000-0000-0002-000000000001', '00000000-0000-0000-0000-000000000001', 100, NOW())
ON CONFLICT (id) DO NOTHING;

-- -------------------------------------------------------------
-- BILLING SUBSCRIPTION (for ENTITLEMENT-001 and BILLING-WEBHOOK-001)
-- Tenant A has an active 'pro' subscription.
-- Tenant B has no subscription (free tier).
-- -------------------------------------------------------------
INSERT INTO subscriptions (id, org_id, provider, provider_subscription_id, plan, status, created_at)
VALUES
  ('00000000-0000-0000-0003-000000000001', '00000000-0000-0000-0000-000000000001', 'stripe', 'sub_BedrockTestA001', 'pro',  'active',   NOW()),
  ('00000000-0000-0000-0003-000000000002', '00000000-0000-0000-0000-000000000002', 'stripe', 'sub_BedrockTestB001', 'free', 'trialing', NOW())
ON CONFLICT (id) DO NOTHING;

-- =============================================================
-- ROLLBACK (swap to COMMIT for iterative testing)
-- =============================================================
ROLLBACK;
```

**Sweep integration:** `sweep.py` executes this before Stage 4 when `--env=staging` and
`needs_seed_data=true` checks are in scope. It reads the connection string from the env
var named in `assets.json → datastores[0].identifier` (looked up as `DATABASE_URL` by
convention). On completion (pass or fail), a `ROLLBACK` is sent automatically unless
`--keep-fixtures` is passed.

**Table-name substitution:** `sweep.py` reads `assets.json → tenant_resources[*].table_or_collection`
and does a find-replace on the `PLACEHOLDER` block before executing, so the same file
covers any schema.

### 2b. `bedrock-stripe-fixture.json` — Stripe CLI billing fixture

Location: `templates/stripe/bedrock-stripe-fixture.json`

Run with: `stripe fixtures templates/stripe/bedrock-stripe-fixture.json`

```json
{
  "_meta": {
    "template_version": 0,
    "description": "Bedrock security: seed a Stripe test customer + subscription for BILLING-WEBHOOK-001 and ENTITLEMENT-001 proofs."
  },
  "fixtures": [
    {
      "name": "bedrock_customer_a",
      "path": "/v1/customers",
      "method": "post",
      "params": {
        "email":    "owner-a@bedrock.test",
        "name":     "Bedrock Tenant A",
        "metadata": { "bedrock_org_id": "00000000-0000-0000-0000-000000000001" }
      }
    },
    {
      "name": "bedrock_price_pro",
      "path": "/v1/prices",
      "method": "post",
      "params": {
        "currency": "usd",
        "unit_amount": 9900,
        "recurring": { "interval": "month" },
        "product_data": { "name": "Bedrock Pro" }
      }
    },
    {
      "name": "bedrock_subscription_a",
      "path": "/v1/subscriptions",
      "method": "post",
      "params": {
        "customer": "${bedrock_customer_a:id}",
        "items": [{ "price": "${bedrock_price_pro:id}" }],
        "metadata": { "bedrock_test": "true" }
      }
    }
  ]
}
```

After `stripe fixtures` runs, `sweep.py` captures `bedrock_subscription_a:id` and
`bedrock_customer_a:id` into `assets.json → tenant_resources` (the billing resource
entries) so webhook tests know which IDs to replay.

**Webhook replay test** (part of `WEBHOOK-001` + `BILLING-WEBHOOK-001`):

```bash
# Generate a real signed event, replay it (valid sig, should succeed):
stripe trigger invoice.payment_succeeded --stripe-account ${STRIPE_ACCOUNT_ID}

# Replay with bad signature (should 400):
curl -X POST ${BASE_URL}/api/webhooks/stripe \
  -H "Stripe-Signature: t=1,v1=deadbeef" \
  -d '{"type":"invoice.payment_succeeded"}'

# Replay same event ID twice (should be idempotent — second call 200 but no state change):
stripe trigger invoice.payment_succeeded  # capture event id
# ... replay same event id via mitmproxy or direct curl with recorded body
```

---

## 3. Enriched `ledger.json` Evidence Schema

The ledger is the single source of truth (Gemini verdict, confirmed by synthesis).
No SARIF, no Jira sync in core. The ledger IS the SLA — RED = CI fails. The enrichment
deepens what each entry proves without adding bureaucracy.

### 3a. Schema (one entry per check)

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "$id": "bedrock-ledger-entry-v2",
  "type": "object",
  "required": ["check_id", "status", "environment", "target"],
  "properties": {

    "check_id":    { "type": "string", "description": "e.g. BOLA-001" },
    "title":       { "type": "string" },
    "domain":      { "type": "string" },
    "severity":    { "type": "string", "enum": ["critical", "high", "medium", "low", "info"] },
    "status":      { "type": "string", "enum": ["PASS", "FAIL", "N-A", "NEEDS-PROOF", "BLOCKED"] },
    "blocked_reason": {
      "type": ["string", "null"],
      "description": "Only set when status=BLOCKED. Machine-readable reason string (see §4b)."
    },

    "environment": { "type": "string", "enum": ["pre-commit", "ci", "preview", "staging", "prod"] },
    "target":      { "type": "string", "description": "The URL or path tested" },

    "tool": {
      "type": ["string", "null"],
      "description": "The tool that produced this result (from strategy[] winner), e.g. gitleaks, pytest, nuclei, manual"
    },
    "command": {
      "type": ["string", "null"],
      "description": "The exact command run. Reproducible by anyone with env access."
    },
    "started_at":  { "type": ["string", "null"], "format": "date-time" },
    "ended_at":    { "type": ["string", "null"], "format": "date-time" },

    "observed": {
      "type": ["string", "null"],
      "description": "What actually happened. Concrete: HTTP status, tool output excerpt, test assertion result."
    },
    "expected": {
      "type": ["string", "null"],
      "description": "What was required for PASS. Directly maps to pass_criteria in registry.yaml."
    },
    "negative_control": {
      "type": ["string", "null"],
      "description": "What the negative control proved. The thing that would pass if the vulnerability existed."
    },

    "evidence_files": {
      "type": "array",
      "items": { "type": "string" },
      "description": "Relative paths (from the .bedrock/ dir) to captured artifacts: test output, screenshots, pcap excerpts, tool reports."
    },

    "triage_class": {
      "type": ["integer", "null"],
      "enum": [null, 1, 2, 3, 4, 5],
      "description": "Class 1-5 per PROTOCOL.md §5. Only populated on FAIL entries after triage."
    },
    "triage_notes": { "type": ["string", "null"] },

    "risk": {
      "type": ["string", "null"],
      "enum": [null, "accepted", "mitigated", "open"],
      "description": "Human decision on a FAIL. 'accepted' requires expiry + owner."
    },
    "owner": {
      "type": ["string", "null"],
      "description": "Person/team responsible for resolving this finding."
    },
    "expiry": {
      "type": ["string", "null"],
      "format": "date",
      "description": "ISO date after which a suppressed/accepted finding must be re-reviewed."
    },

    "regression_test_path": {
      "type": ["string", "null"],
      "description": "If the proof was promoted to the project's own test suite, its relative path."
    },
    "oracle": {
      "type": "array",
      "items": { "type": "string" },
      "description": "External authority ids from registry.yaml, e.g. ['OWASP API1:2023', 'CWE-639']"
    },
    "confidence": {
      "type": "string",
      "enum": ["auto", "auto-low", "agent"],
      "description": "Runner confidence: auto = deterministic probe; auto-low = absence-of-evidence; agent = human/agent closed."
    }
  }
}
```

### 3b. Example: BOLA-001 green entry (PASS with full evidence)

```json
{
  "check_id": "BOLA-001",
  "title": "Object authz — cross-identity access returns indistinguishable 404",
  "domain": "access-control",
  "severity": "critical",
  "status": "PASS",
  "blocked_reason": null,

  "environment": "staging",
  "target": "https://staging.my-saas.com/api/invoices/inv_aaa111aaa111aaa111aaa111aaa11100",

  "tool": "vitest",
  "command": "vitest run templates/typescript-node/bola.test.ts",
  "started_at": "2026-06-21T10:15:02Z",
  "ended_at":   "2026-06-21T10:15:09Z",

  "observed": "Member-B token → GET /api/invoices/inv_aaa111... → 404 {\"error\":\"not found\"}. Body identical to nonexistent resource response. Owner-A token → same resource → 200 with full payload.",
  "expected": "Status 404, body indistinguishable from nonexistent resource. Owner-A can access. No 403 status-code leak.",
  "negative_control": "Owner-A token can reach /api/invoices/inv_aaa111... → 200 with invoice payload. Confirmed defence does not break legitimate access.",

  "evidence_files": [
    "evidence/BOLA-001/vitest-output.txt",
    "evidence/BOLA-001/member-b-response.json",
    "evidence/BOLA-001/owner-a-response.json"
  ],

  "triage_class": null,
  "triage_notes": null,
  "risk": null,
  "owner": null,
  "expiry": null,
  "regression_test_path": "tests/security/bola.test.ts",

  "oracle": ["OWASP API1:2023", "CWE-639"],
  "confidence": "agent"
}
```

### 3c. Example: SEC-LEAK-001 BLOCKED entry

```json
{
  "check_id": "SEC-LEAK-001",
  "title": "No secret present in source or git history",
  "domain": "secrets-logging",
  "severity": "critical",
  "status": "BLOCKED",
  "blocked_reason": "strategy_tool_missing:trufflehog,gitleaks — no eligible tool found; degrading to NEEDS-PROOF",

  "environment": "ci",
  "target": "/home/runner/work/my-saas",

  "tool": null,
  "command": "trufflehog git file://. --only-verified",
  "started_at": null,
  "ended_at": null,
  "observed": null,
  "expected": "Zero verified secrets in repo history.",
  "negative_control": null,
  "evidence_files": [],
  "triage_class": null, "triage_notes": null,
  "risk": "open", "owner": null, "expiry": null,
  "regression_test_path": null,
  "oracle": ["CWE-532"], "confidence": "auto"
}
```

### 3d. BLOCKED reason format (machine-readable, parseable by `server.py`)

```
blocked_reason format: "<category>:<detail>"

Categories:
  dep_failed:<check_id>          INV-001 failed; this check required it
  dep_needs_proof:<check_id>     upstream still NEEDS-PROOF
  env_mismatch:<env>             check requires staging but --env=preview
  needs_seed_data:missing        seed_bedrock.sql not run or fixtures absent
  needs_asset_type:<type>        assets.json has no entries for this type (clean-floor path)
  strategy_tool_missing:<tools>  all strategy options unavailable (no tools found)
  stage_gate:<gate_id>           SCOPE-001/DEPLOY-GATE-001 not yet PASS
```

---

## 4. `server.py` DAG-Progress Console — State Model

### 4a. Design contract

The console is NOT 76 flat rows. It is a **programme dashboard** showing where the sweep
is in the pipeline, what is blocked and why, and the single next action that moves things
forward fastest.

Layout (served at `http://127.0.0.1:8765`):

```
╔═══════════════════════════════════════════════════════════════════════════════╗
║  BEDROCK SECURITY — staging — my-saas                            [GREEN / RED] ║
╚═══════════════════════════════════════════════════════════════════════════════╝

  Stage 0   SCOPE & SAFETY    ██████████ PASS (2/2)
  Stage 1   FRAME             ██████████ PASS (8/8)  → assets.json written
  Stage 2   STATIC            ████████░░ 14/16  [2 BLOCKED: tool missing]
  Stage 3   DYNAMIC-PASSIVE   ░░░░░░░░░░ WAITING — preview URL not set
  Stage 4   DYNAMIC-ADVERSARIAL ░░░░░░░░░░ BLOCKED — seed data required
  Stage 5   LLM/AI            ░░░░░░░░░░ N/A — no LLM surface in assets.json
  Stage 6   DECISION/VERDICT  ░░░░░░░░░░ WAITING

  ─────────────────────────────────────────────────────────────────────────────
  OPEN ITEMS (14)
  ─────────────────────────────────────────────────────────────────────────────
  ⛔ CRITICAL   BOLA-001       NEEDS-PROOF   staging   [not yet run]
  ⛔ CRITICAL   RACE-001       NEEDS-PROOF   staging   [not yet run]
  ⚠  HIGH       DEP-001        BLOCKED       ci        strategy_tool_missing:osv-scanner,npm-audit
  ✔  PASS       SEC-LEAK-001   PASS          ci        gitleaks (auto)
  …

  ─────────────────────────────────────────────────────────────────────────────
  ▶ NEXT SAFEST USEFUL ACTION
  ─────────────────────────────────────────────────────────────────────────────
  Run 14 STATIC checks that are ready now (no seed data, no live URL needed):
  → python sweep.py . --env=ci --run-commands

  ─────────────────────────────────────────────────────────────────────────────
  ⚠ BLOCKED WITH REASON
  ─────────────────────────────────────────────────────────────────────────────
  DEP-001 — Missing tools: osv-scanner, npm audit
  → Install: pip install osv-scanner   OR   npm install -g npm (already available?)
  → [INSTALL osv-scanner]  [SKIP — mark NEEDS-PROOF]

  Stage 4 adversarial suite (BOLA-001, RACE-001, 23 others) — Seed data missing
  → Fixtures not seeded. Run:
      psql $DATABASE_URL -f templates/supabase-postgres/seed_bedrock.sql
  → [GENERATE SEED COMMAND]  [SHOW seed_bedrock.sql]

  Stage 3 dynamic-passive — Preview URL not set
  → Set BEDROCK_PREVIEW_URL or pass --preview-url=https://...
  → [SET URL]
```

### 4b. Console state model (internal, drives the render)

```python
# engine/console_state.py

from dataclasses import dataclass, field
from typing import Optional
from enum import Enum

class StageState(Enum):
    WAITING    = "waiting"     # upstream stage not done
    RUNNING    = "running"     # currently executing
    PASS       = "pass"        # all checks green
    PARTIAL    = "partial"     # some pass, some blocked/open
    BLOCKED    = "blocked"     # cannot start; explicit blocker
    NA         = "na"          # no applicable checks in this stage (clean floor)
    FAIL       = "fail"        # at least one hard fail

@dataclass
class StageStatus:
    stage_num:   int
    name:        str
    state:       StageState
    total:       int = 0
    passed:      int = 0
    failed:      int = 0
    blocked:     int = 0
    na:          int = 0
    blocker_msg: Optional[str] = None  # human-readable if state=BLOCKED
    asset_note:  Optional[str] = None  # e.g. "→ assets.json written (12 routes)"

@dataclass
class BlockedItem:
    check_id:     str
    reason:       str            # parsed from ledger blocked_reason
    action_type:  str            # "install_tool" | "run_seed" | "set_env" | "run_stage" | "manual"
    action_label: str            # button label
    action_cmd:   Optional[str]  # shell command if action_type == "run_*"

@dataclass
class ConsoleState:
    target:       str
    environment:  str
    overall:      str            # "GREEN" | "RED"
    stages:       list[StageStatus] = field(default_factory=list)
    open_items:   list[dict]     = field(default_factory=list)   # ledger entries where status != PASS/NA
    blocked_items:list[BlockedItem] = field(default_factory=list)
    next_action:  Optional[str] = None   # The single best next command to run
    next_action_cmd: Optional[str] = None
```

### 4c. "Run next safest useful action" algorithm

The console computes `next_action` by walking this priority ladder:

```python
def compute_next_action(state: ConsoleState) -> tuple[str, str]:
    """
    Returns (label, command) for the single best next move.
    Priority: unblock gates → run ready checks → generate fixtures → install tools → manual triage.
    """
    # 1. Stage gate blockers (SCOPE-001, DEPLOY-GATE-001) — highest priority
    for item in state.blocked_items:
        if item.action_type == "run_stage" and "SCOPE" in item.check_id:
            return "Complete scope/safety gate first", f"# Answer: do you own {state.target}? Set BEDROCK_TARGET_CONFIRMED=true"

    # 2. CI/static checks ready to run (no seed data, no live URL)
    ready_static = [s for s in state.stages if s.name == "STATIC" and s.state in (StageState.WAITING, StageState.PARTIAL)]
    if ready_static:
        return (
            f"Run {ready_static[0].total - ready_static[0].passed} STATIC checks ready now",
            f"python sweep.py . --env=ci --run-commands"
        )

    # 3. Seed data missing
    if any(b.action_type == "run_seed" for b in state.blocked_items):
        return (
            "Generate and run seed fixtures",
            f"psql $DATABASE_URL -f templates/supabase-postgres/seed_bedrock.sql"
        )

    # 4. Tool missing — install suggestion
    tool_blockers = [b for b in state.blocked_items if b.action_type == "install_tool"]
    if tool_blockers:
        tool_names = ", ".join(b.action_cmd for b in tool_blockers[:3] if b.action_cmd)
        return (
            f"Install missing tools: {tool_names}",
            tool_blockers[0].action_cmd or ""
        )

    # 5. Preview URL not set — dynamic-passive checks waiting
    if any(s.state == StageState.BLOCKED and "preview" in (s.blocker_msg or "") for s in state.stages):
        return (
            "Set preview URL to unlock dynamic checks",
            "export BEDROCK_PREVIEW_URL=https://your-preview.vercel.app"
        )

    # 6. Staging adversarial ready (seed done, URL set)
    adversarial_stage = next((s for s in state.stages if "ADVERSARIAL" in s.name), None)
    if adversarial_stage and adversarial_stage.state == StageState.WAITING:
        return (
            "Run adversarial suite against staging",
            "python sweep.py . --env=staging --run-commands"
        )

    # 7. Default: show open NEEDS-PROOF items for manual triage
    open_needs_proof = [i for i in state.open_items if i["status"] == "NEEDS-PROOF"]
    if open_needs_proof:
        check = open_needs_proof[0]["check_id"]
        return (
            f"Manually close {check} — copy template and run against real routes",
            f"# See templates/ for {check} proof template"
        )

    return ("Review ledger", "cat .bedrock/LEDGER.md")
```

### 4d. Install-missing-tool button

When a check is BLOCKED due to `strategy_tool_missing`, the console renders an actionable
panel. The install commands are keyed from a registry in `engine/tools.py`:

```python
TOOL_INSTALL = {
    "gitleaks":    "brew install gitleaks   # or: go install github.com/gitleaks/gitleaks/v8@latest",
    "trufflehog":  "pip install trufflehog  # or: brew install trufflehog",
    "semgrep":     "pip install semgrep",
    "nuclei":      "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
    "osv-scanner": "go install github.com/google/osv-scanner/cmd/osv-scanner@latest",
    "checkdmarc":  "pip install checkdmarc",
    "sslyze":      "pip install sslyze",
    "dnsx":        "go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
    "stripe":      "brew install stripe/stripe-cli/stripe",
    "jwt_tool":    "pip install jwt_tool",
    "k6":          "brew install k6",
}
```

Clicking "INSTALL" in the browser renders the exact install command. Clicking "SKIP" marks
that check as NEEDS-PROOF with `confidence: auto` and moves on.

### 4e. Generate-missing-fixture button

When Stage 4 is BLOCKED due to `needs_seed_data:missing`:

1. Console shows a "GENERATE SEED COMMAND" button.
2. Clicking it renders the `psql $DATABASE_URL -f ...` command with the actual `DATABASE_URL`
   variable name (not the value — never the value).
3. A "SHOW seed_bedrock.sql" link opens the template in-browser (syntax-highlighted).
4. A "SHOW Stripe fixture" link renders the JSON for copy-paste to `stripe fixtures`.

---

## 5. Proof → Regression Test-Runner Integration

### 5a. The `bedrock-pytest` plugin

When a green adversarial proof exists (status=PASS, `confidence: agent`, tool=pytest),
`server.py` offers to promote it into the project's own test suite:

```
  ✔ BOLA-001 passed — promote to project regression suite?
  → [COPY TO tests/security/bola.test.ts]
```

Clicking generates:

```python
# engine/promote.py

import shutil, pathlib, json

def promote_proof_to_regression(check_id: str, out_dir: pathlib.Path, project_root: pathlib.Path):
    """
    Copies the template proof that ran for check_id into tests/security/ in the
    project root, updating the ledger entry with regression_test_path.
    """
    ledger_path = out_dir / "ledger.json"
    ledger = json.loads(ledger_path.read_text())

    entry = next((e for e in ledger if e["check_id"] == check_id), None)
    if not entry or entry["status"] != "PASS":
        raise ValueError(f"{check_id} is not PASS — cannot promote")

    # Determine source template
    template_dir = pathlib.Path(__file__).parent.parent / "templates"
    # Pick best template for detected stack (from assets.json)
    assets = json.loads((out_dir / "assets.json").read_text())
    framework = assets.get("stack", {}).get("framework", "")
    stack_map = {"nextjs": "typescript-node", "express": "typescript-node",
                 "fastapi": "python-fastapi", "fastify": "typescript-node"}
    stack = stack_map.get(framework, "python-fastapi")

    src = template_dir / stack / f"test_{check_id.lower().replace('-','_')}.py"
    if not src.exists():
        src = template_dir / stack / f"{check_id.lower().replace('-','_')}.test.ts"
    if not src.exists():
        raise FileNotFoundError(f"No template found for {check_id} in stack {stack}")

    dest_dir = project_root / "tests" / "security"
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / src.name
    shutil.copy2(src, dest)

    # Update ledger
    entry["regression_test_path"] = str(dest.relative_to(project_root))
    ledger_path.write_text(json.dumps(ledger, indent=2))

    return dest
```

### 5b. `bedrock-pytest` plugin (Python / pytest)

Ships as `engine/plugins/conftest_bedrock.py`. Projects drop this into their `conftest.py`
or add `--co -p engine.plugins.conftest_bedrock` to their `pytest.ini`.

```python
# engine/plugins/conftest_bedrock.py
"""
pytest plugin: runs any security proof test in tests/security/ and
emits a structured result that updates .bedrock/ledger.json on pass/fail.

Usage:
  1. Copy or symlink this file to your project's conftest.py (or import it there).
  2. Run: pytest tests/security/ -v
  3. Results flow into .bedrock/ledger.json automatically.
"""
import pytest, json, datetime, pathlib, os

LEDGER_PATH = pathlib.Path(os.environ.get("BEDROCK_OUT", ".bedrock")) / "ledger.json"

def _load_ledger():
    if LEDGER_PATH.exists():
        return json.loads(LEDGER_PATH.read_text())
    return []

def _save_ledger(entries):
    LEDGER_PATH.parent.mkdir(parents=True, exist_ok=True)
    LEDGER_PATH.write_text(json.dumps(entries, indent=2))

@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    report = outcome.get_result()

    # Only act on security proof tests (marked with @pytest.mark.bedrock or in tests/security/)
    is_bedrock = (
        "tests/security" in str(item.fspath) or
        item.get_closest_marker("bedrock") is not None
    )
    if not is_bedrock or call.when != "call":
        return

    check_id = item.get_closest_marker("bedrock").args[0] if item.get_closest_marker("bedrock") else "UNKNOWN"

    status = "PASS" if report.passed else "FAIL"
    evidence = str(report.longrepr) if not report.passed else None

    entries = _load_ledger()
    existing = next((e for e in entries if e.get("check_id") == check_id), None)

    now = datetime.datetime.utcnow().isoformat() + "Z"
    if existing:
        existing["status"] = status
        existing["ended_at"] = now
        existing["tool"] = "pytest"
        existing["command"] = f"pytest {item.fspath}::{item.name}"
        existing["confidence"] = "agent"
        if evidence:
            existing["observed"] = evidence[:2000]   # truncate for ledger
    else:
        entries.append({
            "check_id": check_id, "status": status, "tool": "pytest",
            "command": f"pytest {item.fspath}::{item.name}",
            "ended_at": now, "confidence": "agent",
            "observed": evidence[:2000] if evidence else None,
            "evidence_files": [], "oracle": []
        })

    _save_ledger(entries)
```

Usage in a proof test:

```python
# tests/security/test_bola.py
import pytest

@pytest.mark.bedrock("BOLA-001")
def test_bola_cross_tenant_returns_indistinguishable_404():
    """
    Oracle: OWASP API1:2023 / CWE-639
    Member-B token must receive a response indistinguishable from a nonexistent resource
    when requesting an object owned by Tenant A.
    """
    import httpx, json
    assets = json.loads(open(".bedrock/assets.json").read())
    base = assets["target"]["base_url"]
    token_b = __import__("os").environ[assets["roles"][1]["token_env"]]
    obj_a_id = assets["tenant_resources"][0]["test_object_a_id"]

    # Negative control: use owner-A token — must succeed
    token_a = __import__("os").environ[assets["roles"][0]["token_env"]]
    r_owner = httpx.get(f"{base}/api/invoices/{obj_a_id}", headers={"Authorization": f"Bearer {token_a}"})
    assert r_owner.status_code == 200, "Negative control failed: owner cannot reach own resource"

    # Adversarial: member-B token on owner-A object — must look like nonexistent
    r_other = httpx.get(f"{base}/api/invoices/{obj_a_id}", headers={"Authorization": f"Bearer {token_b}"})
    r_ghost  = httpx.get(f"{base}/api/invoices/doesnotexist-000000000000", headers={"Authorization": f"Bearer {token_b}"})

    assert r_other.status_code == r_ghost.status_code,   "Status code leaks object existence"
    assert r_other.json() == r_ghost.json() or r_other.text == r_ghost.text, \
        "Response body leaks object existence"
    assert r_other.status_code != 403, "403 leaks object existence (should be 404 or 200 with empty body)"
```

### 5c. `bedrock-vitest` plugin (TypeScript / Vitest)

Ships as `engine/plugins/bedrock-vitest.ts`. Projects add `reporters: ['./node_modules/bedrock-security/engine/plugins/bedrock-vitest']` to `vitest.config.ts`.

```typescript
// engine/plugins/bedrock-vitest.ts
import type { Reporter, TestCase, TestModule } from 'vitest/reporters';
import fs from 'fs';
import path from 'path';

const LEDGER_PATH = process.env.BEDROCK_OUT
  ? path.join(process.env.BEDROCK_OUT, 'ledger.json')
  : '.bedrock/ledger.json';

function loadLedger(): any[] {
  if (fs.existsSync(LEDGER_PATH)) {
    return JSON.parse(fs.readFileSync(LEDGER_PATH, 'utf8'));
  }
  return [];
}

function saveLedger(entries: any[]): void {
  fs.mkdirSync(path.dirname(LEDGER_PATH), { recursive: true });
  fs.writeFileSync(LEDGER_PATH, JSON.stringify(entries, null, 2));
}

export default class BedrockVitestReporter implements Reporter {
  onFinished(files?: TestModule[]): void {
    if (!files) return;
    const ledger = loadLedger();
    const now = new Date().toISOString();

    for (const file of files) {
      // Only process files in tests/security/
      if (!file.moduleId.includes('tests/security')) continue;

      for (const task of file.children.values()) {
        if (task.type !== 'test') continue;
        // Extract check_id from test name, e.g. "[BOLA-001] cross-tenant..."
        const match = task.name.match(/^\[([A-Z]+-\d+)\]/);
        const checkId = match ? match[1] : 'UNKNOWN';
        const status = task.result?.state === 'pass' ? 'PASS' : 'FAIL';
        const existing = ledger.find(e => e.check_id === checkId);
        const entry = existing ?? { check_id: checkId, oracle: [], evidence_files: [] };
        entry.status = status;
        entry.tool = 'vitest';
        entry.command = `vitest run ${file.moduleId}`;
        entry.ended_at = now;
        entry.confidence = 'agent';
        if (status === 'FAIL' && task.result?.errors?.[0]) {
          entry.observed = task.result.errors[0].message?.slice(0, 2000);
        }
        if (!existing) ledger.push(entry);
      }
    }
    saveLedger(ledger);
  }
}
```

Usage:

```typescript
// tests/security/bola.test.ts
import { describe, it, expect } from 'vitest';
import assets from '../../.bedrock/assets.json';

describe('[BOLA-001] Object authz — cross-tenant access indistinguishable', () => {
  const BASE_URL = assets.target.base_url;
  const ownerRole  = assets.roles.find(r => r.name === 'owner')!;
  const memberRole = assets.roles.find(r => r.name === 'member')!;
  const resource   = assets.tenant_resources[0];

  it('member-B cannot distinguish A-owned object from nonexistent', async () => {
    const TOKEN_B = process.env[memberRole.token_env!]!;
    const TOKEN_A = process.env[ownerRole.token_env!]!;

    // Negative control
    const ownerRes = await fetch(`${BASE_URL}/api/invoices/${resource.test_object_a_id}`,
      { headers: { Authorization: `Bearer ${TOKEN_A}` } });
    expect(ownerRes.status).toBe(200);  // owner CAN reach their own resource

    // Adversarial
    const otherRes = await fetch(`${BASE_URL}/api/invoices/${resource.test_object_a_id}`,
      { headers: { Authorization: `Bearer ${TOKEN_B}` } });
    const ghostRes = await fetch(`${BASE_URL}/api/invoices/doesnotexist-000000000000`,
      { headers: { Authorization: `Bearer ${TOKEN_B}` } });

    expect(otherRes.status).not.toBe(403);   // 403 leaks existence
    expect(otherRes.status).toBe(ghostRes.status);
    expect(await otherRes.text()).toBe(await ghostRes.text());
  });
});
```

---

## 6. The Clean-Floor Guarantee

### 6a. Contract

> An empty or N/A surface must cause `sweep.py` to exit 0 in under 3 seconds.
> Every domain skip must be proven by the *absence of the surface* in `assets.json`,
> not by silence.

This is Gemini's "lighter than air when nothing is wrong" rule, now formalised as a
testable contract. It ensures the tool is not punishing to adopt on small/clean codebases.

### 6b. Short-circuit logic in `sweep.py`

```python
# engine/sweep.py — after FRAME stage writes assets.json

DOMAIN_TO_ASSET_SECTION = {
    "access-control":   lambda a: a["routes"] and a["tenant_resources"],
    "authn-session-jwt":lambda a: a["token_types"],
    "ssrf-webhook-idem":lambda a: a["external_fetches"] or a["webhooks"],
    "secrets-logging":  lambda a: a["secrets"],
    "llm-ai":           lambda a: a["llm_surfaces"],
    "rate-abuse":       lambda a: a["routes"],   # any routes → could have rate limit
    "injection-input":  lambda a: a["routes"],
    "headers-cors-csrf":lambda a: bool(a["target"].get("base_url")),
    "deploy-ops":       lambda a: a["deploy_targets"],
    "client-exposure":  lambda a: any(s["exposed_client"] for s in a["secrets"]),
    "deps-supplychain": lambda a: True,          # always applicable
}

def domain_has_surface(domain: str, assets: dict) -> bool:
    fn = DOMAIN_TO_ASSET_SECTION.get(domain)
    if fn is None:
        return True   # unknown domain: assume applicable (conservative)
    return bool(fn(assets))

def resolve_check(check: dict, assets: dict, ledger: list) -> dict:
    """Returns a ledger entry. Fast-paths N/A if surface is absent."""
    domain = check.get("domain", "")
    if not domain_has_surface(domain, assets):
        return {
            "check_id": check["id"],
            "status": "N-A",
            "confidence": "auto-low",
            "observed": f"No {domain} surface detected in assets.json — {_surface_proof(domain, assets)}",
            "expected": "Surface absent → check not applicable",
        }
    # ... normal resolution
```

The `_surface_proof(domain, assets)` function generates the N/A evidence string:

```python
def _surface_proof(domain: str, assets: dict) -> str:
    """Returns a human-readable proof of why the surface is absent."""
    proofs = {
        "llm-ai":           f"llm_surfaces: [] — no LLM calls detected across {len(assets['routes'])} routes",
        "ssrf-webhook-idem":f"external_fetches: [] and webhooks: [] — no outbound or inbound HTTP detected",
        "authn-session-jwt":f"token_types: [] — no JWT/token minting found in codebase",
        "client-exposure":  f"No client-exposed env vars found (no NEXT_PUBLIC_/VITE_ prefixes)",
    }
    return proofs.get(domain, f"assets.{domain} is empty or not populated")
```

### 6c. Performance contract

The 3-second budget is measured against an empty test repo with:
- 0 routes
- 0 token types
- 0 webhooks / external fetches
- 0 LLM surfaces
- 0 datastores
- `--env=ci` (no live probes)

Stages 0–1 run fast (file glob + grep). If FRAME returns empty assets, all Stage 2–5
checks short-circuit to N/A via the `domain_has_surface` gate. Stage 6 decision checks
(DEC-001/002, CSRF-001, TRIAGE-001) are skipped because there is nothing to decide on.

Expected timing on an empty repo:
- FRAME (INV-001..008): ~0.8s (glob + light grep)
- STATIC short-circuit: ~0.3s (antipattern greps on empty tree)
- N/A resolution for Stages 3–5: ~0.05s each
- Total: ~1.5–2.0s

A benchmark test ships in `tests/test_clean_floor.py`:

```python
# tests/test_clean_floor.py
import subprocess, time, tempfile, pathlib

def test_clean_floor_exits_zero_under_3s():
    """An empty repo must exit 0 in under 3 seconds."""
    with tempfile.TemporaryDirectory() as tmp:
        p = pathlib.Path(tmp)
        (p / "README.md").write_text("# Empty")  # one file
        start = time.monotonic()
        result = subprocess.run(
            ["python", "engine/sweep.py", str(p), "--env=ci", "--json-only"],
            capture_output=True, timeout=10
        )
        elapsed = time.monotonic() - start
        assert result.returncode == 0, f"Unexpected non-zero exit: {result.stderr.decode()}"
        assert elapsed < 3.0, f"Clean-floor took {elapsed:.2f}s — must be under 3s"
```

### 6d. N/A evidence in the ledger

Every N/A entry from the clean-floor path must carry `confidence: auto-low` and a
non-empty `observed` field. This makes "N/A" auditable — it is not a silent skip, it is
a proven-absent surface. Example:

```json
{
  "check_id": "LLM-INJ-001",
  "status": "N-A",
  "confidence": "auto-low",
  "observed": "llm_surfaces: [] — no LLM calls detected across 0 routes",
  "expected": "Surface absent → check not applicable",
  "tool": "sweep.py-frame",
  "evidence_files": []
}
```

On a strict sweep (`--strict`), the runner prints these N/A entries and invites the user
to confirm them by reading the relevant sections of code — Gemini's `auto-low` pattern.

---

## 7. File Map — What Ships Where

```
engine/
  assets.py                   AssetWriter + AssetWriter.load()
  console_state.py            StageStatus, BlockedItem, ConsoleState dataclasses
  tools.py                    TOOL_INSTALL registry (install commands)
  promote.py                  promote_proof_to_regression()
  plugins/
    conftest_bedrock.py       pytest plugin (drop into conftest.py)
    bedrock-vitest.ts         Vitest reporter plugin

templates/
  supabase-postgres/
    seed_bedrock.sql          Rollback-wrapped tenant A/B + quota + billing rows
  stripe/
    bedrock-stripe-fixture.json  Stripe CLI fixture (customer + sub)

tests/
  test_clean_floor.py         Clean-floor guarantee benchmark

.bedrock/                     (written by sweep.py to the target repo)
  assets.json                 FRAME output — attack surface map
  ledger.json                 Enriched evidence ledger (this spec §3)
  LEDGER.md                   Human-readable ledger (generated from ledger.json)
  evidence/
    {check_id}/               Captured artifacts per check
```

---

## 8. Summary for the Build Contract

Three deliverables, each a hard dependency for the next:

1. **`assets.json`** — the single artefact that makes adversarial tests non-fictional.
   Without it, every template is a placeholder; with it, templates wire themselves. FRAME
   must write a valid, schema-conforming `assets.json` before any Stage 2+ check runs.

2. **Fixtures** — `seed_bedrock.sql` and `bedrock-stripe-fixture.json` are the only things
   that let BOLA, RACE, WEBHOOK, ENTITLEMENT, and BILLING-WEBHOOK run automatically rather
   than waiting for a human to manually create test state. Both are rollback-wrapped and
   idempotent.

3. **Enriched `ledger.json`** — the deepened evidence schema (with `observed`, `expected`,
   `negative_control`, `tool`, `command`, timestamps, `blocked_reason`, `regression_test_path`)
   is what turns "the test passed" into a reproducible, auditable proof. It is not bureaucracy;
   it is the artefact that lets a new engineer trust the sweep result.

The console (`server.py`) and test-runner plugins are the delivery mechanism for (3) —
they read and write `ledger.json` and present its state as action-oriented UX rather than a
status table.
