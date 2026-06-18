"""
AUTHN-REQUIRED-001 — every data endpoint requires authentication.
Oracle: OWASP API2:2023 (Broken Authentication), OWASP A01:2021.

The "Postman test" from the wild: hit each data endpoint with NO credentials. A
secure endpoint returns 401 (or 403) — never 200-with-data. An open endpoint lets
ANY unauthenticated user query your database.

Drive this from the route inventory produced in Stage 0 (INV-001). List every
non-public route here; the test fires each anonymously and asserts it is rejected.
"""
import pytest

# TODO: paste the route inventory from the frame stage. Mark genuinely public routes
# (health, login, signup, public landing data) in PUBLIC so they're excluded.
DATA_ROUTES = [
    ("GET", "/api/users"),
    ("GET", "/api/users/1"),
    ("GET", "/api/orders"),
    ("POST", "/api/orders"),
    ("GET", "/api/me"),
    # ... every route that reads or mutates owned/tenant data
]
PUBLIC = {
    ("POST", "/api/login"),
    ("POST", "/api/signup"),
    ("GET", "/health"),
}


@pytest.mark.parametrize("method,path", [r for r in DATA_ROUTES if tuple(r) not in PUBLIC])
def test_endpoint_rejects_unauthenticated(client, method, path):
    """No Authorization header, no cookie -> must be 401/403, never 200-with-data."""
    resp = client.request(method, path)  # deliberately NO auth
    assert resp.status_code in (401, 403), (
        f"{method} {path} is OPEN: returned {resp.status_code} to an unauthenticated "
        f"request. Any anonymous user can reach this data. Add a default-deny auth guard."
    )
    # Belt-and-braces: even on an unexpected 200, there must be no data body.
    if resp.status_code == 200:
        body = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else resp.text
        assert not body, f"{method} {path} returned data without authentication"


def test_public_routes_still_work(client):
    """Over-correction guard: genuinely public routes must remain reachable."""
    for method, path in PUBLIC:
        if method == "GET":
            assert client.get(path).status_code < 500
