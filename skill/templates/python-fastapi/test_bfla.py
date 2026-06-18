"""
BFLA-001 — Function authz: lower-role token cannot reach admin/owner routes (OWASP API5:2023).

PROVE: a VALID, fully-authenticated lower-role token (user_b is a plain member, not
admin/owner) is rejected with 403 on EVERY admin/owner-only route — for both read and
write methods. Authentication is not authorization: a real token must not be mistaken
for a privileged one. Function-level authz must be enforced server-side, not by hiding
the button in the UI.

Wire the TODOs (routes + a privileged actor live in conftest.py / below).
"""
import pytest

# TODO: list EVERY function-gated route (admin or owner-only). Include writes —
#   missing authz on a state-changing route is the worst case.
PRIVILEGED_ROUTES = [
    ("GET", "/api/admin/users", None),
    ("GET", "/api/admin/metrics", None),
    ("POST", "/api/admin/users/1/ban", {"reason": "x"}),
    ("DELETE", "/api/admin/users/1", None),
    ("PATCH", "/api/admin/settings", {"flag": True}),
]


@pytest.fixture
def admin(client):
    """An ACTUAL privileged actor — the over-correction guard needs a real admin.
    TODO: seed/login a user whose role is admin/owner; return {id, token, headers}."""
    raise NotImplementedError("Seed a real admin and return its auth headers.")


@pytest.mark.parametrize("method,path,body", PRIVILEGED_ROUTES)
def test_lower_role_token_is_forbidden(client, user_b, method, path, body):
    """user_b holds a genuine member token — privileged routes must answer 403."""
    resp = client.request(method, path, json=body, headers=user_b["headers"])
    assert resp.status_code == 403, (
        f"{method} {path}: a valid LOWER-ROLE token got {resp.status_code}, not 403. "
        f"Function-level authz is missing — authentication was treated as authorization."
    )


@pytest.mark.parametrize("method,path,body", PRIVILEGED_ROUTES)
def test_not_merely_404_or_401(client, user_b, method, path, body):
    """A privileged-but-authenticated caller must be 403, never silently 401/404
    (which would mean the route is simply unauthenticated, not role-gated)."""
    resp = client.request(method, path, json=body, headers=user_b["headers"])
    assert resp.status_code not in (200, 201), f"{method} {path}: privileged action ALLOWED for member"


def test_admin_still_reaches_admin_routes(client, admin):
    """Over-correction guard: the legitimate admin must NOT be locked out."""
    resp = client.get("/api/admin/users", headers=admin["headers"])
    assert resp.status_code == 200, "authz over-corrected: real admin is blocked"
