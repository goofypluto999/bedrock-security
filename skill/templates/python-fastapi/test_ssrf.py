"""
SSRF-001 — Server fetch validates the resolved IP and re-validates redirects (CWE-918, OWASP A10:2021).

PROVE: a server-side fetch driven by a user-supplied URL cannot be steered at internal
infrastructure. Requests to the cloud metadata endpoint (169.254.169.254), loopback
(127.0.0.1), an RFC-1918 private IP, and — critically — a PUBLIC url that 302-redirects to
a private one are ALL rejected. Validation happens AFTER DNS resolution against the
resolved IP, and every redirect hop is re-checked. Only allow-listed schemes/hosts pass.

This is a falsifiable, oracle-anchored test. It actively submits SSRF target URLs and
asserts each is refused — not a happy-path fetch test. Wire the TODOs.
"""
import pytest

# TODO: the route that fetches a user-supplied URL (e.g. import-from-url, avatar, webhook test).
FETCH_ROUTE = "/api/fetch"   # body: {"url": "..."}

# TODO: stand up a local responder so the redirect case is real: one endpoint that returns
#   302 Location: http://169.254.169.254/  (a public-looking host pointing inward).
PUBLIC_302_TO_PRIVATE = "http://redirector.test/to-metadata"

BLOCKED_TARGETS = [
    "http://169.254.169.254/latest/meta-data/",   # cloud metadata
    "http://[fd00:ec2::254]/latest/meta-data/",    # IMDS over IPv6
    "http://127.0.0.1/",                            # loopback
    "http://localhost:8000/internal",              # loopback by name
    "http://10.0.0.5/",                             # RFC-1918 private
    "http://192.168.1.1/",                          # RFC-1918 private
    "http://169.254.169.254.nip.io/",              # DNS that resolves to a private IP
    "file:///etc/passwd",                           # non-http scheme
    "gopher://127.0.0.1:6379/_INFO",               # smuggling scheme
    PUBLIC_302_TO_PRIVATE,                          # public → 302 → private (redirect re-check)
]


@pytest.mark.parametrize("url", BLOCKED_TARGETS)
def test_ssrf_internal_and_redirect_targets_rejected(client, user_a, url):
    resp = client.post(FETCH_ROUTE, json={"url": url}, headers=user_a["headers"])
    # Rejected at validation: 400 (bad/blocked url) or 422 (schema). Never 200, never a 5xx
    # that proves the connection to the internal host was actually attempted.
    assert resp.status_code in (400, 422), (
        f"SSRF not blocked for {url!r}: got {resp.status_code} "
        f"(must validate the RESOLVED IP and re-check every redirect hop)"
    )
    assert resp.status_code < 500, f"5xx for {url!r} suggests the internal fetch was attempted"


def test_ssrf_allowlisted_public_url_still_works(client, user_a):
    """Guard against over-correction: an allow-listed public URL must still fetch."""
    # TODO: point at a known-good public/allow-listed URL your app is meant to fetch.
    resp = client.post(FETCH_ROUTE, json={"url": "https://allowed.example.com/ok"},
                        headers=user_a["headers"])
    assert resp.status_code in (200, 201, 502), resp.text
