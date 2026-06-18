"""
ERRORLEAK-001 — Error responses are sanitized (OWASP A05:2021, CWE-209).

PROVE: triggering errors hands the client a generic message + safe status — never a stack
trace, SQL/driver text, a filesystem path, or framework internals. A forced 500 (unhandled
server fault) and a 4xx (malformed input) are both inspected: the body must contain none of
the leak markers below. Raw errors are a free map of the system for an attacker; detail
belongs in server-side logs + a correlation id, not the response.

This is a falsifiable, oracle-anchored test: it provokes faults and asserts the body leaks
nothing internal. Wire the TODOs (a route that 500s on bad input + a 4xx route).
"""
import pytest

# TODO: a route + payload that provokes an UNHANDLED server error (500).
CRASH_ROUTE = "/api/objects"
CRASH_PAYLOAD = {"name": {"unexpected": "object-where-string-required"}}
# TODO: a route that returns a 4xx for malformed input.
BAD_INPUT_ROUTE = "/api/objects"
BAD_INPUT_PAYLOAD = {"name": 12345}

# Markers that betray internal detail if echoed to the client.
LEAK_MARKERS = [
    "traceback", "stack trace", 'file "', "line ", "/usr/", "c:\\",
    "sqlstate", "psycopg", "sqlalchemy", "syntax error at", "ora-",
    "site-packages", "uvicorn", "fastapi", ".py\", line",
]


def _assert_no_leak(resp, where):
    low = resp.text.lower()
    for marker in LEAK_MARKERS:
        assert marker not in low, (
            f"{where}: internal detail leaked ({marker!r}) in {resp.status_code} body. "
            f"Return a generic message + correlation id; log the detail server-side only."
        )


def test_server_error_body_is_generic(client, user_a):
    resp = client.post(CRASH_ROUTE, json=CRASH_PAYLOAD, headers=user_a["headers"])
    # A 422 (validation caught it) is fine; if it 500s, the body must still be clean.
    assert resp.status_code in (400, 422, 500), resp.status_code
    _assert_no_leak(resp, "500 path")


def test_client_error_body_is_generic(client, user_a):
    resp = client.post(BAD_INPUT_ROUTE, json=BAD_INPUT_PAYLOAD, headers=user_a["headers"])
    assert resp.status_code in (400, 422), resp.status_code
    _assert_no_leak(resp, "4xx path")


def test_not_found_is_generic(client, user_a):
    """A 404 for a non-existent route must also stay generic (no framework debug page)."""
    resp = client.get("/api/this-route-does-not-exist-xyz", headers=user_a["headers"])
    assert resp.status_code == 404
    _assert_no_leak(resp, "404 path")
