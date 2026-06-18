-- RACE-001 / atomic quota-debit — TOCTOU defense at the database.
-- Stack: Supabase / Postgres. Proves a balance debit cannot oversell under
-- concurrency and can never go negative.
--
-- Run against a TEST/STAGING DB. Two parts:
--   (1) the CORRECT pattern (single guarded UPDATE) you should ship, and
--   (2) the proof: a negative balance is impossible, and concurrent debits serialize.
--
-- TODO: replace `accounts(id, balance)` and the cost with your schema.

-- ===========================================================================
-- (1) THE CORRECT PATTERN — guard in the WHERE, react to the row count.
-- ===========================================================================
-- WRONG (check-then-act, racy):
--   select balance from accounts where id = :id;     -- both readers see 1
--   update accounts set balance = balance - 1 ...;    -- both debit -> -1
--
-- RIGHT (atomic; only debits if the guard still holds at write time):
--   update accounts set balance = balance - :cost
--    where id = :id and balance >= :cost;             -- guard in WHERE
--   -- if row count = 0 -> insufficient/lost-the-race -> return 402, client re-reads.

-- ===========================================================================
-- (2) PROOF: balance can never go negative.
-- ===========================================================================
begin;

create temporary table accounts (id int primary key, balance int not null check (balance >= 0)) on commit drop;
insert into accounts values (1, 5);   -- balance N = 5

-- Debit 6 times; the 6th must fail to update (guard blocks it), not go negative.
do $$
declare i int; affected int; ok int := 0; denied int := 0;
begin
  for i in 1..6 loop
    update accounts set balance = balance - 1 where id = 1 and balance >= 1;
    get diagnostics affected = row_count;
    if affected = 1 then ok := ok + 1; else denied := denied + 1; end if;
  end loop;

  if ok <> 5 then
    raise exception 'oversell: % debits succeeded against a balance of 5', ok;
  end if;
  if denied <> 1 then
    raise exception 'expected exactly 1 denial after balance hit 0, got %', denied;
  end if;
  if (select balance from accounts where id = 1) <> 0 then
    raise exception 'final balance is not 0';
  end if;
end $$;

-- The CHECK (balance >= 0) is the backstop: even a buggy debit path raises rather
-- than persisting a negative balance. Keep it as defense-in-depth.

rollback;

-- ===========================================================================
-- TRUE CONCURRENCY (cannot be shown in one session — do this to fully prove it):
--   Session 1:  begin; update accounts set balance = balance-1 where id=1 and balance>=1;  -- hold
--   Session 2:  update accounts set balance = balance-1 where id=1 and balance>=1;  -- BLOCKS on the row lock
--   Session 1:  commit;   Session 2 then proceeds against the post-commit balance.
-- The row lock serializes the writers; neither can read-then-write past the guard.
-- ===========================================================================
