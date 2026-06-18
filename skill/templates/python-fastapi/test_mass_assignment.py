"""
MASS-001 — Mass assignment: privileged fields are ignored, not bound (OWASP API6:2023).

PROVE: a normal user POSTing privileged fields they must never control
(role, plan, is_admin, tenant_id) cannot set them. The server ignores/rejects those
keys; a RE-FETCH proves the stored value is unchanged. The falsifiable property: the
client cannot escalate by smuggling extra body keys into a model bind
(.dict()/model_dump()/**payload). Input schemas must be explicit allow-lists
(extra=forbid), never the raw ORM model.

Wire the TODOs (the self-update route + how to read role/plan back).
"""
import pytest

PRIVILEGED_FIELDS = {
    "role": "admin",
    "plan": "enterprise",
    "is_admin": True,
    "tenant_id": "00000000-0000-0000-0000-000000000000",
}


def _read_self(client, headers):
    """Re-fetch the caller's own record — the unchanged-value oracle.
    TODO: point at your real /me (or equivalent) endpoint."""
    r = client.get("/api/me", headers=headers)
    assert r.status_code == 200, r.text
    return r.json()


@pytest.mark.parametrize("field,evil", list(PRIVILEGED_FIELDS.items()))
def test_privileged_field_not_bound_on_update(client, user_b, field, evil):
    """user_b tries to escalate via a profile update. TODO: real self-update route."""
    before = _read_self(client, user_b["headers"])
    # Smuggle the privileged key alongside a legitimate one.
    payload = {"display_name": "totally-normal", field: evil}
    resp = client.patch("/api/me", json=payload, headers=user_b["headers"])
    # Either silently ignored (200) or hard-rejected (422 extra=forbid) — never bound.
    assert resp.status_code in (200, 422), f"unexpected {resp.status_code} for {field}: {resp.text}"
    after = _read_self(client, user_b["headers"])
    assert after.get(field) == before.get(field), (
        f"MASS ASSIGNMENT: client set '{field}' to {after.get(field)!r} via the request body. "
        f"Bind an explicit input schema with extra=forbid, not the ORM model."
    )


def test_create_cannot_self_assign_privilege(client, user_b):
    """The create path is the other classic miss — extra keys must not stick."""
    resp = client.post("/api/me/profile", json={"bio": "hi", "is_admin": True},
                        headers=user_b["headers"])
    if resp.status_code in (200, 201):
        assert resp.json().get("is_admin") in (False, None), "is_admin bound on create"


def test_legit_field_still_updates(client, user_b):
    """Over-correction guard: a normal, allowed field must still save."""
    resp = client.patch("/api/me", json={"display_name": "Bea"}, headers=user_b["headers"])
    assert resp.status_code == 200
    assert _read_self(client, user_b["headers"]).get("display_name") == "Bea"
