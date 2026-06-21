-- SBA-ANON-001 — Supabase anon key present but a table is missing RLS (instant DB compromise)
-- Oracle: OWASP API1:2023, CWE-284.
--
-- PROVE: every table reachable by the `anon` role has Row-Level Security enabled
-- (pg_class.relrowsecurity = true) AND at least one RLS policy. A single table without
-- RLS is a full-table data dump for anyone who knows the anon key — which is public by
-- design in Supabase client SDKs.
--
-- Additionally: an anon cross-tenant read attempt must return 0 rows.
--
-- Run in the Supabase SQL editor or psql AGAINST A READ-ONLY / STAGING schema.
-- The BEGIN/ROLLBACK wrapper ensures zero data mutation.
-- Wire the TODOs to your schema before running.

begin;

-- ── 1. Enumerate every table the anon role can reach (SELECT privilege) ──────

-- Build a result set: table name + whether RLS is on + whether a policy exists.
-- Any row with rls_enabled = false is a Class-1 finding.

do $$
declare
  rec     record;
  bad     text := '';
begin
  for rec in
    select
      c.relname                                                     as table_name,
      c.relrowsecurity                                              as rls_enabled,
      exists (
        select 1 from pg_policies p
        where p.tablename = c.relname
          and p.schemaname = 'public'
      )                                                             as has_policy
    from pg_class c
    join pg_namespace n on n.oid = c.relnamespace
    where n.nspname = 'public'
      and c.relkind = 'r'                                          -- ordinary tables only
      -- Only tables the anon role can SELECT from:
      and has_table_privilege('anon', c.oid, 'SELECT')
    order by c.relname
  loop
    if not rec.rls_enabled then
      bad := bad || rec.table_name || ' (RLS disabled); ';
    end if;
    if rec.rls_enabled and not rec.has_policy then
      bad := bad || rec.table_name || ' (RLS on but NO policy = full block, not isolation); ';
    end if;
  end loop;

  if bad <> '' then
    raise exception
      'SBA-ANON-001 FAIL — anon-readable tables with missing/incomplete RLS: %'
      E'\nFix: ALTER TABLE <name> ENABLE ROW LEVEL SECURITY; '
      E'\n      CREATE POLICY anon_select ON <name> FOR SELECT USING (false); '
      E'\n  or the correct scoped policy for your access model.',
      bad;
  end if;
end $$;

-- ── 2. Cross-tenant anon read must return 0 rows ─────────────────────────────

-- Simulate an unauthenticated anon request (no auth.uid()).
-- With correct RLS the anon role must see zero rows in the objects table.
-- TODO: replace `objects` with a real tenant-owned table in your schema.

set local role anon;

do $$
declare
  n int;
begin
  -- auth.uid() is NULL for the anon role — a correct RLS policy of
  --   USING (owner_id = auth.uid())
  -- returns zero rows when uid is NULL.
  select count(*) into n from public.objects;  -- TODO: replace `objects`
  if n <> 0 then
    raise exception
      'SBA-ANON-001 CROSS-TENANT FAIL — anon role can read % row(s) from public.objects. '
      'RLS policy must not permit reads when auth.uid() IS NULL. '
      'Fix: add "AND auth.uid() IS NOT NULL" to the USING clause, or use a dedicated '
      'anon policy that returns only explicitly public rows.',
      n;
  end if;
end $$;

-- Restore role before rollback.
reset role;

rollback;  -- never persist; this script is read-only proof work

-- ── Expected outcome ─────────────────────────────────────────────────────────
-- No exceptions raised => every anon-reachable table has RLS enabled + a policy,
-- and anon cannot read cross-tenant rows (count = 0). PROVEN.
--
-- If any raise exception fires:
--   Class-1 finding (critical). Remediation per table:
--     ALTER TABLE <name> ENABLE ROW LEVEL SECURITY;
--     CREATE POLICY tenant_isolation ON <name>
--       FOR ALL USING (owner_id = auth.uid());
--   Re-run this script after each fix. All exceptions must be silent before PASS.
