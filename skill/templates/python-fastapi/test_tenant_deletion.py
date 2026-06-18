"""
TENANT-DEL-001 — Cross-tenant deletion safety: deleting A leaves B untouched (OWASP API1:2023, GDPR Art.17).

PROVE: seeding two tenants and deleting tenant A changes ZERO rows belonging to tenant B.
A miscoped cascade (FK ON DELETE CASCADE crossing the tenant boundary, or an unscoped
DELETE) is the falsifiable failure: B's row counts drop, or B's objects stop being
readable, after A is deleted. We assert B's per-table counts are BYTE-IDENTICAL
before/after and that B can still read its own objects.

Wire the TODOs (seed routes, the delete-tenant call, B's tables, B's read path).
"""
import pytest

# TODO: every table that holds tenant-owned rows; we count B's rows before/after.
B_OWNED_TABLES = ["projects", "comments", "uploads", "members"]


def _count_b_rows(client, user_b, table):
    """Count B-owned rows in `table` via an admin/diagnostic read scoped to B.
    TODO: replace with a real scoped count (API call or test-only SELECT helper)."""
    r = client.get(f"/api/_test/count?table={table}&tenant={user_b['id']}",
                   headers=user_b["headers"])
    assert r.status_code == 200, r.text
    return r.json()["count"]


@pytest.fixture
def two_tenants(client, user_a, user_b):
    """Seed comparable data under BOTH tenants so a cross-tenant cascade has something
    of B's to destroy. TODO: real creation calls for each tenant."""
    for owner in (user_a, user_b):
        client.post("/api/projects", json={"name": f"p-{owner['id']}"}, headers=owner["headers"])
        client.post("/api/uploads", json={"blob": "x"}, headers=owner["headers"])
    return user_a, user_b


def test_deleting_tenant_a_leaves_b_byte_identical(client, two_tenants):
    user_a, user_b = two_tenants
    before = {t: _count_b_rows(client, user_b, t) for t in B_OWNED_TABLES}

    # Delete tenant A entirely. TODO: the real account/tenant-deletion route.
    resp = client.delete(f"/api/tenants/{user_a['id']}", headers=user_a["headers"])
    assert resp.status_code in (200, 202, 204), f"delete A failed: {resp.status_code} {resp.text}"

    after = {t: _count_b_rows(client, user_b, t) for t in B_OWNED_TABLES}
    assert after == before, (
        f"CROSS-TENANT CASCADE: deleting A changed B's row counts {before} -> {after}. "
        f"Scope the cascade to the tenant boundary; never let A's deletion reach B's rows."
    )


def test_b_objects_still_readable_after_a_deleted(client, two_tenants):
    """Over-correction guard + integrity: B's own data must remain fully usable."""
    user_a, user_b = two_tenants
    client.delete(f"/api/tenants/{user_a['id']}", headers=user_a["headers"])
    listing = client.get("/api/projects", headers=user_b["headers"])
    assert listing.status_code == 200, "B can no longer read its own projects after A's deletion"
    assert len(listing.json()) >= 1, "B's objects vanished — collateral deletion across tenants"
