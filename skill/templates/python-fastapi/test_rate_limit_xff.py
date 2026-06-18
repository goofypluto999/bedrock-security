"""
RATE-001 — Rate limit holds on authed identity under XFF rotation (OWASP API4:2023, RFC 6585).

PROVE: an authenticated caller who fires N+1 requests cannot evade the limit by spoofing
a fresh client IP on each request. Rotating X-Forwarded-For / X-Real-IP must NOT reset
the counter, because the limiter keys on the authenticated identity (not a client-
controlled header). The (N+1)th request returns 429 AND carries a Retry-After header.
A spoofable-IP key is the falsifiable failure: the (N+1)th would 200 with rotated XFF.

Wire the TODOs (the limited route + its per-window limit N).
"""
import pytest

# TODO: a rate-limited route + its documented per-window cap.
LIMITED_PATH = "/api/expensive"   # e.g. an LLM or write endpoint
LIMIT_N = 5

SPOOFED_IPS = ["203.0.113.{}".format(i) for i in range(LIMIT_N + 1)]


def _hit(client, headers, ip):
    """One request from the same identity but a forged source IP."""
    h = dict(headers)
    h["X-Forwarded-For"] = ip
    h["X-Real-IP"] = ip
    return client.get(LIMITED_PATH, headers=h)


def test_limit_holds_despite_xff_rotation(client, user_a):
    """Burn the budget under N+1 calls, each claiming a different client IP."""
    statuses = [_hit(client, user_a["headers"], ip).status_code for ip in SPOOFED_IPS[:LIMIT_N]]
    assert all(s != 429 for s in statuses), f"throttled early within budget: {statuses}"
    blocked = _hit(client, user_a["headers"], SPOOFED_IPS[LIMIT_N])
    assert blocked.status_code == 429, (
        f"IP-spoof bypass: the {LIMIT_N + 1}th request returned {blocked.status_code}, not 429. "
        f"Re-key the limiter on the authed identity and parse XFF only from trusted proxies."
    )
    assert "retry-after" in {k.lower() for k in blocked.headers}, (
        "429 is missing Retry-After (RFC 6585) — clients cannot back off correctly."
    )


def test_second_identity_has_its_own_budget(client, user_a, user_b):
    """Over-correction guard: keying on identity must NOT bleed across users.
    A's exhausted budget must not throttle B's very first request."""
    for ip in SPOOFED_IPS:
        _hit(client, user_a["headers"], ip)   # exhaust + overflow A
    first_b = _hit(client, user_b["headers"], "198.51.100.7")
    assert first_b.status_code != 429, "limiter is global, not per-identity — innocent B was blocked"
