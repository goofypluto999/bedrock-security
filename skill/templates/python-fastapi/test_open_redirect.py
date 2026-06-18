"""
REDIRECT-001 — No open redirect on user-supplied redirect/next URLs (CWE-601, OWASP A01:2021).

PROVE: an attacker-controlled redirect target cannot send a user to an external host. An
absolute external URL, a protocol-relative `//evil.com`, a backslash trick, and a
userinfo-spoof must be rejected or forced to a known-safe local path — never reflected into
a Location header pointing off-origin (the OAuth-token-theft / phishing vector). Relative
in-app paths still redirect, so the allow-list is host-based, not a blanket block.

This is a falsifiable, oracle-anchored test: it feeds hostile redirect targets and asserts
the response never redirects off-origin. Wire the TODOs.
"""
import pytest

# TODO: the route that consumes a redirect/next/returnTo param.
REDIRECT_ROUTE = "/api/login"             # TODO: real route honoring the param
REDIRECT_PARAM = "next"                   # TODO: real param name (next/redirect/returnTo)
SAFE_HOSTS = {"app.example.com", ""}      # TODO: your own origin host(s); "" == relative

EXTERNAL_TARGETS = [
    "https://evil.com/phish",
    "//evil.com",                          # protocol-relative
    "https:evil.com",                      # malformed scheme
    "/\\evil.com",                         # backslash bypass
    "https://app.example.com.evil.com",    # suffix-confusion
    "https://app.example.com@evil.com",    # userinfo spoof
]


def _location_host(resp):
    loc = resp.headers.get("location", "")
    from urllib.parse import urlparse
    return urlparse(loc.replace("\\", "/")).hostname or ""


@pytest.mark.parametrize("target", EXTERNAL_TARGETS)
def test_external_redirect_rejected(client, target):
    resp = client.get(REDIRECT_ROUTE, params={REDIRECT_PARAM: target},
                       follow_redirects=False)
    if resp.status_code in (301, 302, 303, 307, 308):
        assert _location_host(resp) in SAFE_HOSTS, (
            f"OPEN REDIRECT: {target!r} produced Location host {_location_host(resp)!r}. "
            f"Allow-list redirect hosts; default to a known-safe path."
        )
    else:
        assert resp.status_code in (400, 422), f"unexpected {resp.status_code} for {target!r}"


def test_relative_path_still_allowed(client):
    """Over-correction guard: a same-app relative path must still be honored."""
    resp = client.get(REDIRECT_ROUTE, params={REDIRECT_PARAM: "/dashboard"},
                      follow_redirects=False)
    assert resp.status_code != 400, "relative in-app redirect was rejected — allow-list too strict"
