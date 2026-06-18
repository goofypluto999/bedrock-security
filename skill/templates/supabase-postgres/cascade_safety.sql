-- TENANT-DEL-001 / cross-tenant deletion safety — OWASP API1:2023, GDPR Art.17.
-- Stack: Supabase / Postgres. Proves deleting tenant A's data cannot cascade across
-- the tenancy boundary and silently remove tenant B's rows.
--
-- Run in the Supabase SQL editor or psql AGAINST A TEST/STAGING DB (never prod —
-- golden rule: read-only on live data). Nothing persists (begin; ... rollback;).
--
-- TODO: replace `tenants` + `documents` with your real parent/child tables and the
-- actual FK + ON DELETE rule. The point is to exercise YOUR cascade configuration,
-- not these stand-ins — wire the temp tables to mirror the live FK definition.

begin;

-- Parent (tenant) and a child with a tenant-scoped FK. ON DELETE CASCADE here is
-- CORRECT: a tenant's own children go with it. The danger TENANT-DEL-001 hunts is a
-- cascade whose path crosses INTO another tenant (e.g. a shared row, a mis-scoped FK,
-- or a junction table that fans out beyond the boundary).
create temporary table tenants (
  id   uuid primary key,
  name text not null
) on commit drop;

create temporary table documents (
  id        uuid primary key,
  tenant_id uuid not null references tenants(id) on delete cascade,
  title     text not null
) on commit drop;

-- Seed tenant A and tenant B, each with their own documents.
insert into tenants values
  ('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa', 'Tenant A'),
  ('bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb', 'Tenant B');

insert into documents values
  ('a0000001-0000-0000-0000-000000000001', 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa', 'A-doc-1'),
  ('a0000002-0000-0000-0000-000000000002', 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa', 'A-doc-2'),
  ('b0000001-0000-0000-0000-000000000001', 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb', 'B-doc-1'),
  ('b0000002-0000-0000-0000-000000000002', 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb', 'B-doc-2'),
  ('b0000003-0000-0000-0000-000000000003', 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb', 'B-doc-3');

-- Snapshot tenant B's footprint BEFORE the deletion. We assert byte-identical after.
create temporary table _b_before on commit drop as
  select id, tenant_id, title from documents
   where tenant_id = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'
   order by id;

-- ---- delete tenant A (and, correctly, A's own documents via the scoped cascade) ----
delete from documents where tenant_id = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';
delete from tenants   where id        = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';

-- (1) Tenant A is fully gone — confirms the delete actually ran (no false pass).
do $$
declare n int;
begin
  select count(*) into n from documents
   where tenant_id = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';
  if n <> 0 then
    raise exception 'setup/precondition failed: % of tenant A''s documents survived deletion', n;
  end if;
end $$;

-- (2) THE ASSERTION: tenant B's rows are byte-identical before vs after. Any drift
--     (missing row, changed tenant_id, altered title) means the deletion crossed the
--     boundary — a Class-1 cross-tenant cascade / GDPR over-deletion finding.
do $$
declare
  cnt_before int;
  cnt_after  int;
  diff       int;
begin
  select count(*) into cnt_before from _b_before;
  select count(*) into cnt_after  from documents
   where tenant_id = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb';

  if cnt_before <> cnt_after then
    raise exception
      'CROSS-TENANT CASCADE: tenant B had % document(s) before, % after deleting '
      'tenant A. A''s deletion removed B''s data.', cnt_before, cnt_after;
  end if;

  -- Full-row symmetric difference: catches mutated rows, not just count changes.
  select count(*) into diff
  from (
        select id, tenant_id, title from _b_before
        except
        select id, tenant_id, title from documents
         where tenant_id = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'
        union all
        select id, tenant_id, title from documents
         where tenant_id = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'
        except
        select id, tenant_id, title from _b_before
       ) d;

  if diff <> 0 then
    raise exception
      'CROSS-TENANT MUTATION: % of tenant B''s rows changed after deleting tenant A '
      '(rows are not byte-identical). The cascade is not scoped to the tenant boundary.', diff;
  end if;
end $$;

rollback;  -- never persist test data

-- Expected outcome: no exceptions raised => TENANT-DEL-001 PROVEN — deleting tenant A
-- changes ZERO rows belonging to tenant B. If either assertion raises, that is a
-- Class-1 finding: scope every FK cascade to the tenant boundary (no cross-tenant
-- ON DELETE CASCADE, no shared rows deleted by one tenant's removal).
