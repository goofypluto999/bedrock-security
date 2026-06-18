"""
RACE-001 — Quota/balance debit must be atomic under concurrency (TOCTOU).

PROVE: with a balance of exactly N, firing N+1 quota-consuming requests CONCURRENTLY
yields exactly N successes — never N+1 — and the final balance is exactly 0, never
negative. Check-then-act loses this race; a single guarded UPDATE wins it.

This test MUST exercise real concurrency. A single-threaded test client cannot prove
atomicity (that would be a Class-3 environment-only result) — use an async client
with asyncio.gather, or threads against a real (Postgres) DB.
"""
import asyncio

import httpx
import pytest

CONSUME_ROUTE = "/api/consume"  # TODO: the endpoint that debits one unit
N = 5                            # TODO: seed the account with exactly this balance


@pytest.fixture
def funded_user(client, user_a):
    """Seed user_a's balance to exactly N. TODO: real top-up/seed."""
    # set_balance(user_a["id"], N)
    return user_a


@pytest.mark.asyncio
async def test_concurrent_debit_never_oversells(funded_user):
    """Fire N+1 concurrent debits; exactly N must succeed."""
    base_url = "http://test"  # TODO: point at ASGITransport(app=app) or a live test server
    async with httpx.AsyncClient(base_url=base_url) as ac:
        async def hit():
            return await ac.post(CONSUME_ROUTE, headers=funded_user["headers"])

        results = await asyncio.gather(*[hit() for _ in range(N + 1)], return_exceptions=True)

    codes = [r.status_code for r in results if isinstance(r, httpx.Response)]
    successes = sum(1 for c in codes if c == 200)
    denials = sum(1 for c in codes if c in (402, 429))

    assert successes == N, f"oversold: {successes} succeeded against a balance of {N} (TOCTOU race)"
    assert denials >= 1, "the (N+1)th request was not denied — atomic guard missing"
    # TODO: assert the persisted balance is exactly 0 (never negative).
    # assert get_balance(funded_user["id"]) == 0


def test_out_of_balance_is_402_not_403():
    """Out-of-funds is 402 Payment Required (allowed-but-broke), not 403 (not-allowed)."""
    # TODO: drain balance to 0, then one more consume → assert 402.
    pass
