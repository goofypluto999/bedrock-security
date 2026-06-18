"""
BOLA-001 — Object-level authorization (OWASP API1:2023, CWE-639).

PROVE: identity B cannot reach identity A's object by id — on EVERY read AND write
path — and the denial is INDISTINGUISHABLE from "never existed" (same status + body,
not a 403/404 differential that leaks existence).

This is a falsifiable, oracle-anchored test. It tries to BREAK access control, not
confirm the happy path. Wire the TODOs (routes, fixtures live in conftest.py).
"""
import pytest

# TODO: list every route that takes an owned object id — READ and WRITE.
#   The write paths (POST that takes object_id in the body) are the classic miss.
READ_PATHS = [
    "/api/objects/{id}",
    "/api/objects/{id}/export",
]
WRITE_PATHS = [
    ("POST", "/api/objects/{id}/comment", {"text": "x"}),
    ("DELETE", "/api/objects/{id}", None),
]


@pytest.fixture
def a_object(client, user_a):
    """Create an object owned by A; return its id. TODO: real creation call."""
    r = client.post("/api/objects", json={"name": "secret-A"}, headers=user_a["headers"])
    assert r.status_code in (200, 201), r.text
    return r.json()["id"]


def _baseline_missing(client, user_b):
    """B's response for an id that never existed — the indistinguishability oracle."""
    return client.get("/api/objects/999999999", headers=user_b["headers"])


@pytest.mark.parametrize("path", READ_PATHS)
def test_bola_read_returns_indistinguishable_404(client, user_b, a_object, path):
    missing = _baseline_missing(client, user_b)
    resp = client.get(path.format(id=a_object), headers=user_b["headers"])
    # Must be 404 — never 200 (leak) and never 403 (existence oracle).
    assert resp.status_code == 404, f"{path}: expected 404, got {resp.status_code}"
    # Indistinguishable from never-existed: same status AND same body.
    assert resp.status_code == missing.status_code
    assert resp.json() == missing.json(), "denial body differs from non-existent → existence leak"


@pytest.mark.parametrize("method,path,body", WRITE_PATHS)
def test_bola_write_paths_denied(client, user_b, a_object, method, path, body):
    url = path.format(id=a_object)
    resp = client.request(method, url, json=body, headers=user_b["headers"])
    assert resp.status_code == 404, (
        f"{method} {path}: write path leaked/allowed cross-tenant access "
        f"(got {resp.status_code}). Authz-missing-on-write is worse than on read."
    )


def test_owner_still_has_access(client, user_a, a_object):
    """Guard against over-correction: A must still reach A's own object."""
    resp = client.get(f"/api/objects/{a_object}", headers=user_a["headers"])
    assert resp.status_code == 200
