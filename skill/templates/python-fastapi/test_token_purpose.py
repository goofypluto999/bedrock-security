"""
JWT-002 — Token-purpose confusion / 2FA bypass (OWASP API2:2023, RFC 8725 §3.11).

THE marquee check. A real audit found a HIGH-severity 2FA bypass here that five
reviewers missed: the access-token validator checked signature + expiry but NOT what
the token was FOR, so a 2FA-challenge token (minted after password, before TOTP)
authenticated as the full user — TOTP skipped entirely.

PROVE: every non-access token type, used as a Bearer on a protected route, is 401.
Especially the 2FA challenge token taken straight from /login.

Wire the TODOs: how each token type is minted, and a protected route to attack.
"""
import pytest

PROTECTED_ROUTE = "/api/me"  # TODO: any route requiring a real access token


def _mint(client, purpose: str, user) -> str:
    """Return a signed token of the given PURPOSE for `user`. TODO: real mint calls.
    These tokens are validly signed with the auth secret and carry the user's sub —
    that's exactly why a purpose-blind validator wrongly accepts them."""
    raise NotImplementedError(f"Mint a '{purpose}' token via the real code path.")


NON_ACCESS_PURPOSES = ["2fa_challenge", "pw_reset", "email_verify", "magic_link"]


@pytest.mark.parametrize("purpose", NON_ACCESS_PURPOSES)
def test_non_access_token_rejected_on_protected_route(client, user_a, purpose):
    token = _mint(client, purpose, user_a)
    resp = client.get(PROTECTED_ROUTE, headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 401, (
        f"'{purpose}' token authenticated on {PROTECTED_ROUTE} (got {resp.status_code}). "
        f"Token-purpose confusion: the access validator must reject any token whose "
        f"purpose != 'access'."
    )


def test_2fa_challenge_token_cannot_authenticate(client, user_a):
    """The full bypass scenario: login with 2FA on, then replay the challenge token."""
    # TODO: ensure user_a has 2FA enabled, then:
    r = client.post("/api/login", json={"email": user_a["email"], "password": user_a["password"]})
    assert r.status_code == 200 and r.json().get("requires_2fa") is True, r.text
    challenge = r.json()["challenge_id"]  # a JWT signed with the auth secret
    resp = client.get(PROTECTED_ROUTE, headers={"Authorization": f"Bearer {challenge}"})
    assert resp.status_code == 401, (
        "2FA BYPASS: the challenge_id authenticated as the full user — TOTP skipped. "
        "Stamp + require a `purpose` claim per consumer (ideally separate signing keys)."
    )


def test_real_access_token_still_works(client, user_a):
    """Over-correction guard: a genuine access token must still be accepted."""
    token = _mint(client, "access", user_a)
    resp = client.get(PROTECTED_ROUTE, headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
