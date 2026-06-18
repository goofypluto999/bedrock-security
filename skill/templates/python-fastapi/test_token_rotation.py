"""
TOKEN-ROTATE-001 — Refresh-token rotation + working logout (OWASP A07:2021, RFC 9700 / OAuth refresh rotation).

PROVE: a refresh token is single-use. On refresh it ROTATES — the old token is invalidated,
so replaying it is rejected (401). Reuse of an already-rotated token is treated as theft and
REVOKES THE FAMILY: the newest token issued in that chain also stops working. Logout
invalidates the refresh token server-side, not just the client copy. The freshly rotated
token still works once, proving rotation isn't breaking the happy path.

This is a falsifiable, oracle-anchored test: it replays stale/used refresh tokens and asserts
rejection + family revocation. Wire the TODOs (login + refresh + logout routes).
"""
import pytest

REFRESH_ROUTE = "/api/auth/refresh"       # TODO: real refresh route
LOGOUT_ROUTE = "/api/auth/logout"         # TODO: real logout route


def _login(client, user) -> str:
    """Return a fresh refresh token for `user`. TODO: real login returning the refresh token."""
    r = client.post("/api/login", json={"email": user["email"], "password": user["password"]})
    assert r.status_code == 200, r.text
    return r.json()["refresh_token"]


def _refresh(client, token: str):
    return client.post(REFRESH_ROUTE, json={"refresh_token": token})


def test_rotation_invalidates_old_and_revokes_family(client, user_a):
    old = _login(client, user_a)
    first = _refresh(client, old)
    assert first.status_code == 200, f"valid refresh failed ({first.status_code})"
    rotated = first.json()["refresh_token"]
    assert rotated != old, "token did NOT rotate — a stolen refresh token stays valid forever"

    # Replay the consumed token → must be rejected as reuse.
    replay = _refresh(client, old)
    assert replay.status_code == 401, (
        f"reused refresh token accepted ({replay.status_code}) — rotation not enforced."
    )
    # Reuse-detection must revoke the whole family, killing the rotated child too.
    after = _refresh(client, rotated)
    assert after.status_code == 401, (
        "family NOT revoked after reuse — a thief's rotated token still works."
    )


def test_logout_invalidates_refresh_server_side(client, user_a):
    token = _login(client, user_a)
    out = client.post(LOGOUT_ROUTE, headers=user_a["headers"])
    assert out.status_code in (200, 204), out.text
    resp = _refresh(client, token)
    assert resp.status_code == 401, (
        "refresh token still valid after logout — invalidate the session server-side, "
        "not just the client copy."
    )
