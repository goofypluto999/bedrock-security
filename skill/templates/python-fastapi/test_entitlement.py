"""
ENTITLEMENT-001 — Paid-feature access cannot be forged (OWASP API1:2023, API6:2023).

PROVE: a free/lower-tier identity cannot reach a paid feature by any of three attack
vectors: (a) flipping a client-side plan flag in the request body, (b) calling the
gated API endpoint directly with no plan upgrade, (c) supplying tenant B's subscription
id as their own. All three must be denied server-side. A legitimately entitled user
must still succeed — the over-correction guard.

Wire the TODOs (routes, fixture helpers live in conftest.py).
"""
import pytest

# TODO: replace with the real gated endpoint(s) in your app.
#   Any route that checks plan/tier/entitlement server-side belongs here.
GATED_ENDPOINT = "/api/features/export-premium"   # TODO
SUBSCRIPTION_ENDPOINT = "/api/billing/activate"    # TODO: takes subscription_id in body

# TODO: fixture helpers — call your real signup/login endpoints to mint tokens.
# user_a, user_b, and client come from conftest.py already.
# "free_user" is a separate lower-tier account; wire it below.


@pytest.fixture
def free_user(client, assets):
    """A verified free-tier account with no paid subscription."""
    # TODO: sign up a fresh free account or pull from assets["tenants"]["free"].
    #   Must return {id, token, headers} matching the conftest identity shape.
    raise NotImplementedError("Wire a free-tier identity (no paid subscription).")


@pytest.fixture
def paid_subscription_id(user_a, client):
    """Return the subscription_id that belongs to the paid tenant A."""
    # TODO: read it from your billing table, or mint a test subscription for A.
    raise NotImplementedError("Wire a real paid subscription_id owned by user_a.")


# ── Attack vector (a): client-side plan flag flip ─────────────────────────────

def test_client_plan_flag_ignored(client, free_user):
    """Sending plan='pro' in the request body must not upgrade entitlement."""
    # The attack: a free user injects a privileged plan name into the request.
    resp = client.post(
        GATED_ENDPOINT,
        json={"plan": "pro", "tier": "enterprise", "is_premium": True},  # TODO: adjust keys
        headers=free_user["headers"],
    )
    assert resp.status_code in (402, 403, 404), (
        f"Vector (a) FAILED: client plan-flag accepted, got {resp.status_code}. "
        "Server must derive entitlement from its own billing source, not the request body."
    )


# ── Attack vector (b): direct API call with free token ───────────────────────

def test_direct_call_with_free_token_denied(client, free_user):
    """A free token hitting the gated endpoint directly must be rejected."""
    resp = client.post(GATED_ENDPOINT, json={}, headers=free_user["headers"])
    assert resp.status_code in (402, 403, 404), (
        f"Vector (b) FAILED: gated endpoint accessible to free user, got {resp.status_code}. "
        "Server-side entitlement check is missing or wrong."
    )


# ── Attack vector (c): cross-tenant subscription id ──────────────────────────

def test_cross_tenant_subscription_id_denied(client, free_user, paid_subscription_id):
    """Submitting another tenant's subscription_id must not grant entitlement."""
    # The attack: free user supplies A's subscription_id in their own request.
    resp = client.post(
        SUBSCRIPTION_ENDPOINT,
        json={"subscription_id": paid_subscription_id},  # TODO: adjust payload shape
        headers=free_user["headers"],
    )
    # Must be rejected — the server must verify the subscription belongs to the caller.
    assert resp.status_code in (402, 403, 404, 409), (
        f"Vector (c) FAILED: cross-tenant subscription_id accepted, got {resp.status_code}. "
        "Entitlement must be scoped to the authenticated user, not the supplied id."
    )


# ── Over-correction guard: legitimate paid access must still work ─────────────

def test_legitimate_paid_access_succeeds(client, user_a):
    """Regression guard: a legitimately entitled user must reach the gated feature."""
    # user_a is a paid user from conftest — this ensures we haven't over-blocked.
    resp = client.post(GATED_ENDPOINT, json={}, headers=user_a["headers"])
    assert resp.status_code == 200, (
        f"Over-correction: legitimate paid user denied access, got {resp.status_code}. "
        "Fix the entitlement check so real subscribers are not locked out."
    )
