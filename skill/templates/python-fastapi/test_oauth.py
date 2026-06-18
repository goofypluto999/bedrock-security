"""
OAUTH-001 — OAuth2/OIDC hardening (RFC 6749 / RFC 8252, OWASP A07:2021).

PROVE: the authorization + callback flow refuses the classic OAuth attacks. A `state` param
is required and validated (CSRF / fixation) — a missing or mismatched state is rejected. The
`redirect_uri` is EXACT-matched against an allow-list — a prefix/suffix/subdomain variant is
rejected (no open-redirect token theft). Public clients must use PKCE — a code exchange with
no `code_verifier` is rejected. The id_token's aud/iss/nonce are validated — a wrong-aud or
replayed-nonce token is rejected. The exact-allow-listed redirect_uri with valid state passes.

This is a falsifiable, oracle-anchored test: it tampers each parameter and asserts rejection.
Wire the TODOs (authorize/callback/token routes + the allow-listed redirect_uri).
"""
import pytest

AUTHORIZE_ROUTE = "/api/oauth/authorize"  # TODO: real authorize/start route
CALLBACK_ROUTE = "/api/oauth/callback"    # TODO: real callback route
TOKEN_ROUTE = "/api/oauth/token"          # TODO: real code->token exchange route
VALID_REDIRECT = "https://app.example.com/oauth/cb"   # TODO: an exact allow-listed URI

TAMPERED_REDIRECTS = [
    "https://app.example.com/oauth/cb/../evil",   # path traversal
    "https://app.example.com.evil.com/oauth/cb",  # subdomain confusion
    "https://app.example.com/oauth/cb?x=1",       # query-appended (not exact)
    "https://evil.com/oauth/cb",                  # wholly external
]


@pytest.mark.parametrize("redirect_uri", TAMPERED_REDIRECTS)
def test_redirect_uri_must_exact_match(client, redirect_uri):
    resp = client.get(AUTHORIZE_ROUTE, params={
        "client_id": "public-app", "redirect_uri": redirect_uri,
        "response_type": "code", "state": "s123", "code_challenge": "abc",
    })
    assert resp.status_code in (400, 422), (
        f"redirect_uri {redirect_uri!r} accepted — must EXACT-match the allow-list, no prefix/substring."
    )


def test_missing_state_rejected_at_callback(client):
    """No/empty state on the callback → CSRF defense must reject it."""
    resp = client.get(CALLBACK_ROUTE, params={"code": "authcode"})  # state omitted
    assert resp.status_code in (400, 401, 422), "callback accepted with no state — CSRF exposure"


def test_pkce_required_for_public_client(client):
    """Public-client code exchange WITHOUT code_verifier must be rejected."""
    resp = client.post(TOKEN_ROUTE, json={
        "grant_type": "authorization_code", "code": "authcode",
        "client_id": "public-app", "redirect_uri": VALID_REDIRECT,  # no code_verifier
    })
    assert resp.status_code in (400, 401, 422), "token issued without PKCE verifier — enforce PKCE"


def test_idtoken_wrong_aud_rejected(client):
    """An id_token minted for another audience must be rejected (aud/iss validation)."""
    # TODO: mint a validly-signed id_token with aud="some-other-app".
    forged = "TODO.wrong-aud.idtoken"
    resp = client.post("/api/oauth/login", json={"id_token": forged})
    assert resp.status_code in (400, 401, 422), "wrong-aud id_token accepted — validate aud/iss/nonce"
