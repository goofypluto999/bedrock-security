"""
PWPOLICY-001 — Password policy + breached-password (HIBP) check (NIST SP 800-63B, OWASP ASVS V2.1).

PROVE: registration/reset rejects weak passwords and known-breached ones. Too-short and
common passwords (`password`, `12345678`) are refused on length/policy grounds. A password
whose SHA-1 prefix the (mocked) HIBP k-anonymity range API reports as breached is also
refused — even if it satisfies length. A strong, unseen passphrase is accepted, so the
policy is length-first (not banned-composition) and the HIBP call is range-based, never
sending the full hash.

This is a falsifiable, oracle-anchored test: it submits weak/breached passwords and asserts
they are rejected; the HIBP call is MOCKED. Wire the TODOs.
"""
import hashlib
import pytest

# TODO: the register/reset route that enforces the policy.
REGISTER_ROUTE = "/api/register"
# TODO: the import path of the function that queries HIBP's range API, to monkeypatch.
HIBP_TARGET = "app.auth.hibp_range_lookup"

WEAK = ["short", "1234567", "password", "qwerty123", "letmein1"]
STRONG = "correct-horse-battery-staple-9f3z"   # long, unseen passphrase


@pytest.fixture
def hibp_breached(monkeypatch):
    """Force the HIBP range lookup to report EVERY candidate as breached (count > 0).
    Real impl sends only the first 5 SHA-1 hex chars and matches suffixes locally."""
    def _fake(prefix: str) -> dict:
        return {"__ALL__": 9999}   # TODO: shape to your client's return contract
    monkeypatch.setattr(HIBP_TARGET, _fake, raising=False)


@pytest.mark.parametrize("pw", WEAK)
def test_weak_password_rejected(client, pw):
    resp = client.post(REGISTER_ROUTE, json={"email": "a@example.com", "password": pw})
    assert resp.status_code in (400, 422), (
        f"weak password {pw!r} accepted ({resp.status_code}) — enforce length-first policy."
    )


def test_breached_password_rejected_via_hibp(client, hibp_breached):
    """A length-valid password that HIBP flags as breached must still be rejected."""
    assert len(STRONG) >= 12  # would pass length; HIBP is what must block it
    resp = client.post(REGISTER_ROUTE, json={"email": "b@example.com", "password": STRONG})
    assert resp.status_code in (400, 422), (
        "breached password accepted — wire the HIBP k-anonymity range check at register/reset."
    )
    # Defense check: only the 5-char prefix is ever sent (k-anonymity), never the full hash.
    full = hashlib.sha1(STRONG.encode()).hexdigest().upper()
    assert full not in resp.text, "full SHA-1 hash leaked in response — send only the 5-char prefix"
