"""
PAGINATION-001 — Collection endpoints enforce pagination + a max page size (OWASP API4:2023, CWE-770).

PROVE: one request cannot dump the whole table. A list endpoint must cap the page size
server-side — a client asking for limit=10_000_000 (or limit=-1, or no limit at all) is
CAPPED at the documented max, not honored. Returning everything is both data exfiltration
and resource exhaustion. A normal small limit is still respected, so the cap is a ceiling,
not a fixed page.

This is a falsifiable, oracle-anchored test: it requests an absurd page size and asserts the
server refuses to return more than MAX_PAGE. Wire the TODOs (seed > MAX_PAGE rows first).
"""
import pytest

# TODO: the list/collection route + its documented hard max page size.
LIST_ROUTE = "/api/objects"
MAX_PAGE = 100
LIMIT_PARAM = "limit"                     # TODO: real param name (limit/per_page/page_size)


@pytest.fixture
def many_rows(client, user_a):
    """Seed strictly more than MAX_PAGE rows so a cap is observable. TODO: bulk-create."""
    for i in range(MAX_PAGE + 25):
        client.post(LIST_ROUTE, json={"name": f"row-{i}"}, headers=user_a["headers"])


def _count(resp):
    data = resp.json()
    return len(data if isinstance(data, list) else data.get("items", data.get("data", [])))


@pytest.mark.parametrize("huge", [10_000_000, 999999, -1, 0])
def test_huge_limit_is_capped(client, user_a, many_rows, huge):
    resp = client.get(LIST_ROUTE, params={LIMIT_PARAM: huge}, headers=user_a["headers"])
    assert resp.status_code in (200, 400, 422), resp.text[:200]
    if resp.status_code == 200:
        assert _count(resp) <= MAX_PAGE, (
            f"limit={huge} returned {_count(resp)} rows (> max {MAX_PAGE}) — whole-table dump. "
            f"Enforce a server-side max page size."
        )


def test_default_request_is_bounded(client, user_a, many_rows):
    """No client-supplied limit must STILL be bounded — not an implicit dump-all."""
    resp = client.get(LIST_ROUTE, headers=user_a["headers"])
    assert resp.status_code == 200 and _count(resp) <= MAX_PAGE, (
        "unpaginated default returned the whole collection — apply a default page size."
    )
