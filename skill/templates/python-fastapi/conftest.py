"""
TEMPLATE — pytest harness for the Bedrock adversarial suite (Python / FastAPI).

Copy into your `tests/security/` and wire the TODOs to your real app. This harness
bakes in the test-ISOLATION discipline from security-testing-methodology.md §4
(Anti-pattern #13) so that "passes alone / fails in batch" can't hide a real
security regression:

  * one pinned in-memory DB connection for the whole session (StaticPool) so tables
    created on one connection are visible to all,
  * an autouse fixture that RESETS process-global stores (rate-limit counters,
    lockout dict, caches) before each test,
  * two identities (A and B) so every authz test has a second actor to attack with.

Run BOTH orders and require both green (the gate for TEST-ISO-001):
    pytest -p no:randomly tests/security
    pytest -p randomly    tests/security        # pip install pytest-randomly
"""
from __future__ import annotations

import pytest
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool

# TODO: import your FastAPI app, DB Base/session, and token-minting helpers.
# from app.main import app
# from app.db import Base, get_session
# from app.auth import mint_access_token


@pytest.fixture(scope="session")
def engine():
    # Single shared in-memory DB — StaticPool keeps ONE connection so every test
    # session sees the same tables (the #1 root cause of batch-only failures).
    eng = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    # TODO: Base.metadata.create_all(eng)
    return eng


@pytest.fixture
def client(engine):
    """A TestClient/AsyncClient bound to the test DB. Wire your DI override here."""
    # TODO:
    # from fastapi.testclient import TestClient
    # app.dependency_overrides[get_session] = lambda: Session(engine)
    # with TestClient(app) as c:
    #     yield c
    # app.dependency_overrides.clear()
    raise NotImplementedError("Wire the client fixture to your app + test DB.")


@pytest.fixture(autouse=True)
def reset_global_stores():
    """Reset process-global state BEFORE and after every test (Anti-pattern #13)."""
    # TODO: clear rate-limiter storage, lockout counters, LRU caches, etc.
    # from app.ratelimit import _storage; _storage.clear()
    # from app.lockout import _failures; _failures.clear()
    yield
    # TODO: clear again on teardown.


@pytest.fixture
def user_a(client):
    """Seed identity A and return {id, token, headers}. TODO: real signup/login."""
    raise NotImplementedError


@pytest.fixture
def user_b(client):
    """Seed a SECOND identity B — the attacker in every authz test."""
    raise NotImplementedError


def auth(headers_token: str) -> dict:
    return {"Authorization": f"Bearer {headers_token}"}
