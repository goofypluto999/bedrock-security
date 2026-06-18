-- INJ-001 / SQL injection neutralized — OWASP A03:2021, CWE-89.
-- Stack: Supabase / Postgres. Proves a hostile string ("'; DROP ...", "x' OR 1=1 --")
-- bound as a PARAMETER is inert data and cannot alter query structure, whereas the
-- same string concatenated into SQL text does.
--
-- Run in the Supabase SQL editor or psql AGAINST A TEST/STAGING DB (never prod —
-- golden rule: read-only on live data). Nothing persists (begin; ... rollback;).
--
-- TODO: replace `items(id, owner, secret)` with the real table/column you query by a
-- user-supplied string, and mirror the parameterized form your app/driver emits.

begin;

-- Minimal target table + two rows. `secret` is the data an injection would try to leak.
create temporary table items (
  id     int primary key,
  owner  text not null,
  secret text not null
) on commit drop;

insert into items values
  (1, 'alice', 'alice-secret'),
  (2, 'bob',   'bob-secret');

-- The adversarial inputs. Each is a classic payload that breaks naive string-built SQL.
-- We treat them purely as VALUES of the `owner` filter.
--   p1: tautology to dump every row              ->  x' OR '1'='1
--   p2: comment-out the rest of the predicate     ->  alice' --
--   p3: stacked/destructive statement              ->  '; DROP TABLE items; --
--   p4: embedded quote (must round-trip verbatim)  ->  O'Brien

-- ---------------------------------------------------------------------------
-- (1) PARAMETERIZED / SAFE PATH — the pattern your app MUST ship.
--     In SQL we model "bound parameter" with a query-arg ($1) so the payload is
--     never parsed as SQL. The control holds if each payload matches ZERO rows
--     (no row's owner literally equals the payload) and the table still exists.
-- ---------------------------------------------------------------------------
do $$
declare
  payloads text[] := array[
    'x'' OR ''1''=''1',
    'alice'' --',
    '''; DROP TABLE items; --',
    'O''Brien'
  ];
  p text;
  n int;
begin
  foreach p in array payloads loop
    -- USING binds p as data; it can never change the parsed statement.
    execute 'select count(*) from items where owner = $1' into n using p;
    if n <> 0 then
      raise exception
        'INJECTION FAILURE (parameterized path): payload [%] matched % row(s) — '
        'it altered the query instead of being treated as a literal value.', p, n;
    end if;
  end loop;

  -- The "stacked DROP" payload, bound as a parameter, must NOT have dropped the table.
  perform 1 from items where id = 1;
  if not found then
    raise exception
      'INJECTION FAILURE: the destructive payload executed — items row 1 is gone. '
      'A bound parameter must never run as a statement.';
  end if;
end $$;

-- ---------------------------------------------------------------------------
-- (2) DEMONSTRATE THE VULNERABLE PATH (so the proof is falsifiable, not faith).
--     We BUILD the predicate by string concatenation — exactly what you must NOT
--     do — and assert that the tautology payload now leaks BOTH rows. If this
--     somehow returns 0, the demo is broken and we want to know loudly.
--     This block reads only; it never executes the DROP (we concat into a SELECT).
-- ---------------------------------------------------------------------------
do $$
declare
  evil text := 'x'' OR ''1''=''1';        -- the tautology
  built text;
  n int;
begin
  -- WRONG on purpose: interpolating user text straight into SQL.
  built := 'select count(*) from items where owner = ''' || evil || '''';
  execute built into n;
  if n < 2 then
    raise exception
      'DEMO BROKEN: string-built query should have leaked all rows via OR 1=1 '
      '(expected >=2, got %). The contrast that makes this proof meaningful is gone.', n;
  end if;
  -- n >= 2 here is the WHOLE POINT: concatenation is exploitable; parameters are not.
end $$;

rollback;  -- never persist test data

-- Expected outcome: no exceptions raised => INJ-001 PROVEN — parameterized binding
-- neutralizes SQL payloads while string concatenation is demonstrably exploitable.
-- If section (1) raises, that is a Class-1 finding: replace string-built SQL with
-- parameterized queries / the ORM everywhere user input reaches the database.
