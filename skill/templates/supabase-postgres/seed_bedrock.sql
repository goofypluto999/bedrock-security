-- Phase B — canonical seed BODY for the adversarial suite (BOLA / RLS / RACE / TENANT-DEL).
-- The bedrock harness runs this inside a transaction and ROLLS BACK after the checks, so a
-- staging/test database is never actually mutated:
--     begin;  \i seed_bedrock.sql  <run the adversarial checks>  rollback;
-- (Manual one-off: wrap it yourself as above. NEVER run against prod.)
--
-- The ids below are the canonical bedrock fixtures; the sweep records them into
-- `.bedrock/assets.json.tenants` (A.id / B.id) so the per-stack templates target them.
-- TODO: align the table + column names with YOUR schema (tenants/objects/accounts are examples).

-- two tenants (the A/B identities every multi-tenant test attacks across) -------------
insert into tenants (id, name) values
  ('11111111-1111-1111-1111-111111111111', 'bedrock-tenant-A'),
  ('22222222-2222-2222-2222-222222222222', 'bedrock-tenant-B')
on conflict (id) do nothing;

-- one private object per tenant (BOLA-001 / SUPABASE-RLS-001 target) -------------------
insert into objects (id, owner_id, name) values
  ('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa', '11111111-1111-1111-1111-111111111111', 'A-private'),
  ('bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb', '22222222-2222-2222-2222-222222222222', 'B-private')
on conflict (id) do nothing;

-- a quota/balance row for the RACE-001 atomic-debit concurrency test -------------------
insert into accounts (tenant_id, balance) values
  ('11111111-1111-1111-1111-111111111111', 5)
on conflict do nothing;

-- After seeding, mint a real access token per tenant and export them so the templates
-- (conftest.py / *.test.ts) auto-wire their user_a / user_b identities:
--     export BEDROCK_TOKEN_A=<tenant-A access token>
--     export BEDROCK_TOKEN_B=<tenant-B access token>
