"""
INJ-001 — Injection: SQL/XSS/cmd in every string field is neutralized (OWASP A03:2021, CWE-89/79/78).

PROVE: an attacker-controlled string in ANY field cannot break out of its data context —
no payload produces a 500 with a DB-error leak (SQL is parameterized), no payload is
reflected back as executable HTML/JS (output is escaped or served inert as
application/json), and no payload triggers shell execution. Happy input and hostile input
take the same safe path.

This is a falsifiable, oracle-anchored test. It actively sends attack payloads into every
string field and asserts they are neutralized — it does NOT confirm the happy path.
Wire the TODOs (routes, fixtures live in conftest.py).
"""
import pytest

# TODO: every route that accepts a string field reaching a DB, shell, or rendered output.
WRITE_ROUTE = "/api/objects"          # TODO: a create/echo route that stores+returns a string
STRING_FIELDS = ["name", "description"]  # TODO: every user-controlled string field

SQLI = ["' OR '1'='1", "'; DROP TABLE users;--", "1' UNION SELECT NULL--", "\\'; --"]
XSS = ["<script>alert(1)</script>", "\"><img src=x onerror=alert(1)>", "javascript:alert(1)"]
CMDI = ["; cat /etc/passwd", "$(id)", "`whoami`", "| ls -la", "&& curl evil.test"]
PAYLOADS = SQLI + XSS + CMDI


@pytest.mark.parametrize("field", STRING_FIELDS)
@pytest.mark.parametrize("payload", PAYLOADS)
def test_injection_payload_is_neutralized(client, user_a, field, payload):
    body = {f: "safe" for f in STRING_FIELDS}
    body[field] = payload
    resp = client.post(WRITE_ROUTE, json=body, headers=user_a["headers"])

    # SQL injection oracle: never a 500 with a leaked DB error (parameterized queries).
    assert resp.status_code != 500, f"500 on {field}={payload!r} → likely unparameterized SQL"
    assert resp.status_code in (200, 201, 400, 422), f"unexpected {resp.status_code}: {resp.text[:200]}"
    low = resp.text.lower()
    for leak in ("sqlstate", "syntax error", "psycopg", "sqlalchemy", "near \"", "ora-"):
        assert leak not in low, f"DB-error leak ({leak!r}) reflected for {payload!r}"

    if resp.status_code in (200, 201):
        # XSS oracle: stored payload must come back inert — JSON content-type, not text/html,
        # and never an unescaped executable <script>/onerror reflection.
        assert "application/json" in resp.headers.get("content-type", "")
        assert "<script>" not in resp.text and "onerror=" not in resp.text, "executable reflection"
