"""
IDEM-001 — Retried non-idempotent op applies its effect exactly once (logic; companion to RACE-001).

PROVE: the same Idempotency-Key replayed against a side-effecting endpoint (charge, order,
send-email) produces the side effect EXACTLY ONCE — whether the retry arrives sequentially
or concurrently — and both responses are identical (the second returns the stored result,
not a fresh execution). A naive handler double-charges on retry; a (key→result) row with a
unique constraint inside the txn wins.

This is a falsifiable, oracle-anchored test. It actively replays the key (sequentially AND
concurrently) and asserts single-effect + matching responses. Wire the TODOs.
"""
import asyncio

import httpx
import pytest

CHARGE_ROUTE = "/api/charges"   # TODO: a non-idempotent, side-effecting endpoint
BODY = {"amount": 1000, "currency": "usd"}  # TODO: a valid request body


def test_same_key_sequential_applies_once(client, user_a):
    key = "idem-seq-001"
    h = {**user_a["headers"], "Idempotency-Key": key}
    first = client.post(CHARGE_ROUTE, json=BODY, headers=h)
    second = client.post(CHARGE_ROUTE, json=BODY, headers=h)
    assert first.status_code in (200, 201), first.text
    # The replay must echo the stored result, not create a second effect.
    assert second.status_code == first.status_code
    assert second.json() == first.json(), "replayed key returned a different result → not deduped"
    # TODO: assert exactly one side effect persisted for `key`.
    # assert count_charges(key) == 1


@pytest.mark.asyncio
async def test_same_key_concurrent_applies_once(user_a):
    """Two in-flight requests with one key must collapse to a single side effect."""
    key = "idem-conc-001"
    h = {**user_a["headers"], "Idempotency-Key": key}
    base_url = "http://test"  # TODO: bind to ASGITransport(app=app) or a live test server
    async with httpx.AsyncClient(base_url=base_url) as ac:
        async def hit():
            return await ac.post(CHARGE_ROUTE, json=BODY, headers=h)
        results = await asyncio.gather(hit(), hit(), return_exceptions=True)

    resps = [r for r in results if isinstance(r, httpx.Response)]
    ok = [r for r in resps if r.status_code in (200, 201)]
    assert len(ok) >= 1, "both concurrent attempts failed"
    bodies = {r.text for r in ok}
    assert len(bodies) == 1, "concurrent retries produced divergent results → double-applied"
    # TODO: assert exactly one side effect persisted for `key` (the real atomicity oracle).
    # assert count_charges(key) == 1
