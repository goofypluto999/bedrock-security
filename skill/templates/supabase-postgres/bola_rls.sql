-- BOLA-001 / cross-tenant isolation via RLS — OWASP API1:2023, CWE-639
-- Stack: Supabase / Postgres. Proves Row-Level Security actually isolates tenants
-- at the database, not just in the application layer.
--
-- Run in the Supabase SQL editor or psql AGAINST A TEST/STAGING DB (never prod —
-- golden rule: read-only on live data). It simulates two authenticated users and
-- asserts user B cannot read user A's row. Raises an exception (test fails loudly)
-- if isolation is broken.
--
-- TODO: replace `objects`, `owner_id`, and the policy assumptions with your schema.

begin;

-- Simulate the Supabase auth context. auth.uid() reads request.jwt.claims->>'sub'.
-- Two stable fake user ids:
--   A = 11111111-1111-1111-1111-111111111111
--   B = 22222222-2222-2222-2222-222222222222

-- ---- as user A: insert a private row ----
set local role authenticated;
select set_config('request.jwt.claims', '{"sub":"11111111-1111-1111-1111-111111111111"}', true);

insert into objects (owner_id, name)
values ('11111111-1111-1111-1111-111111111111', 'secret-A');

-- A can see their own row:
do $$
declare n int;
begin
  select count(*) into n from objects where name = 'secret-A';
  if n <> 1 then
    raise exception 'RLS too strict: owner A cannot see their own row (got %)', n;
  end if;
end $$;

-- ---- switch to user B: must NOT see A's row ----
select set_config('request.jwt.claims', '{"sub":"22222222-2222-2222-2222-222222222222"}', true);

do $$
declare n int;
begin
  select count(*) into n from objects where name = 'secret-A';
  if n <> 0 then
    raise exception 'BOLA/RLS FAILURE: tenant B can read tenant A''s row (% visible). '
                    'RLS policy does not isolate by owner_id = auth.uid().', n;
  end if;
end $$;

-- B attempting to UPDATE/DELETE A's row must affect 0 rows (write-path isolation):
do $$
declare n int;
begin
  with upd as (
    update objects set name = 'hijacked'
    where owner_id = '11111111-1111-1111-1111-111111111111'
    returning 1
  )
  select count(*) into n from upd;
  if n <> 0 then
    raise exception 'BOLA/RLS WRITE FAILURE: tenant B modified % of tenant A''s rows', n;
  end if;
end $$;

rollback;  -- never persist test data

-- Expected outcome: no exceptions raised => RLS isolation PROVEN for this table.
-- If any `raise exception` fires, that is a Class-1 finding: fix the RLS policy
-- (USING (owner_id = auth.uid())) and the WITH CHECK clause, then re-run.
