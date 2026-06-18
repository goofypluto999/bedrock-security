-- AUDIT-001 / audit log is append-only & survives user deletion — GDPR Art.17(3)(b).
-- Stack: Supabase / Postgres. Proves the application DB role can INSERT audit rows
-- but cannot UPDATE or DELETE them, and that a deleted user's audit events persist
-- with PII scrubbed from the payload.
--
-- Run in the Supabase SQL editor or psql AGAINST A TEST/STAGING DB (never prod —
-- golden rule: read-only on live data). Nothing persists (begin; ... rollback;).
--
-- TODO: replace `app_role` with your real application/anon/authenticated role, and
-- `audit_log` / its columns with the real audit table. The grants below MODEL the
-- intended privilege posture; in production those GRANT/REVOKEs live in a migration,
-- and this script just ASSERTS the role behaves as locked-down.

begin;

-- Stand-in audit table. `actor_id` keeps a (nullable) reference to the user for
-- scrubbing; `payload` is jsonb that must hold NO PII after a deletion request.
create temporary table audit_log (
  id        bigint generated always as identity primary key,
  actor_id  uuid,
  action    text not null,
  payload   jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
) on commit drop;

-- Model the app role and its INTENDED privileges: INSERT + SELECT only.
-- NOTE: temp-table grants to a role are themselves the thing under test — if your
-- real migration accidentally granted UPDATE/DELETE, the assertions below would pass
-- the bad grant, so always run this against the REAL table/role in staging too.
do $$
begin
  if not exists (select 1 from pg_roles where rolname = 'app_role') then  -- TODO: real role
    create role app_role nologin;
  end if;
end $$;

grant insert, select on audit_log to app_role;
-- Deliberately NOT granted: update, delete. (revoke is a no-op if never granted,
-- but we state intent explicitly.)
revoke update, delete on audit_log from app_role;

-- Seed an event that references a user and (wrongly, for now) carries PII in payload.
insert into audit_log (actor_id, action, payload) values
  ('cccccccc-cccc-cccc-cccc-cccccccccccc',
   'login',
   '{"email":"user@example.com","ip":"203.0.113.7"}'::jsonb);

-- ---------------------------------------------------------------------------
-- (1) APPEND-ONLY: as the app role, UPDATE and DELETE must both be denied.
--     We expect SQLSTATE 42501 (insufficient_privilege). If either statement
--     SUCCEEDS, the audit log is mutable by the app => Class-2 finding.
-- ---------------------------------------------------------------------------
set local role app_role;  -- TODO: real role

-- INSERT is allowed (sanity: the role can write new events).
insert into audit_log (actor_id, action) values
  ('cccccccc-cccc-cccc-cccc-cccccccccccc', 'view_dashboard');

-- UPDATE must be blocked.
do $$
begin
  update audit_log set action = 'tampered' where action = 'login';
  raise exception 'AUDIT MUTABLE: app role UPDATED an audit row — log is not append-only.';
exception
  when insufficient_privilege then
    null;  -- expected: privilege correctly withheld
end $$;

-- DELETE must be blocked.
do $$
begin
  delete from audit_log where action = 'login';
  raise exception 'AUDIT MUTABLE: app role DELETED an audit row — log is not append-only.';
exception
  when insufficient_privilege then
    null;  -- expected: privilege correctly withheld
end $$;

reset role;  -- back to the privileged role for the deletion/scrub model

-- ---------------------------------------------------------------------------
-- (2) SURVIVES USER DELETION, PII-SCRUBBED. Simulate a GDPR erasure: the USER is
--     removed, but their audit events REMAIN (Art.17(3)(b) carve-out) — with PII
--     stripped. The scrub nulls actor_id and removes PII keys from payload.
--     (This runs as the privileged/migration role, NOT the app role — scrubbing is
--     a controlled admin operation, never an app capability.)
-- ---------------------------------------------------------------------------
update audit_log
   set actor_id = null,
       payload  = payload - 'email' - 'ip'
 where actor_id = 'cccccccc-cccc-cccc-cccc-cccccccccccc';

do $$
declare
  surviving int;
  leaked    int;
begin
  -- Events still exist after the user is "deleted".
  select count(*) into surviving from audit_log;
  if surviving < 2 then
    raise exception
      'AUDIT LOST ON DELETION: expected the user''s audit events to survive erasure '
      '(>=2 rows), found %.', surviving;
  end if;

  -- No PII remains: no row may still carry email/ip, and no actor_id may point at the user.
  select count(*) into leaked
  from audit_log
  where actor_id = 'cccccccc-cccc-cccc-cccc-cccccccccccc'
     or payload ? 'email'
     or payload ? 'ip';

  if leaked <> 0 then
    raise exception
      'PII NOT SCRUBBED: % audit row(s) still expose the deleted user''s PII '
      '(actor_id or email/ip in payload).', leaked;
  end if;
end $$;

rollback;  -- never persist test data

-- Expected outcome: no exceptions raised => AUDIT-001 PROVEN — the app role cannot
-- UPDATE/DELETE audit rows, a deleted user's audit events persist, and PII is scrubbed
-- from the retained payload. If section (1) raises, revoke UPDATE/DELETE from the app
-- role (and ship to a separate append-only sink); if section (2) raises, retain audit
-- events on user deletion and scrub PII from the payload (GDPR Art.17(3)(b)).
