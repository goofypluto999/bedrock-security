"""
PATHTRAV-001 — Path/directory traversal blocked on any file-path input (CWE-22, OWASP A01:2021).

PROVE: a user-controlled filename/path cannot escape the intended root. `../../etc/passwd`,
URL-encoded `%2e%2e%2f`, double-encoded, backslash, and absolute-path payloads must be
rejected (or canonicalized to stay inside the allow-listed base dir) — never returning the
contents of a file outside the root. A legit in-root filename still resolves, so the guard
canonicalizes rather than blindly blocking every `.` or `/`.

This is a falsifiable, oracle-anchored test: it sends traversal payloads and asserts no file
outside the root is read — it does NOT confirm the happy path only. Wire the TODOs.
"""
import pytest

# TODO: the route that serves/reads a file by a user-supplied name or path param.
FILE_ROUTE = "/api/files/{name}"          # TODO: real download/read route
LEGIT_NAME = "report.txt"                 # TODO: a file that genuinely exists in the root

TRAVERSAL = [
    "../../etc/passwd",
    "..%2f..%2f..%2fetc%2fpasswd",        # url-encoded ../
    "%2e%2e%2f%2e%2e%2fetc%2fpasswd",     # encoded dots + slash
    "..%252f..%252fetc%252fpasswd",       # double-encoded
    "..\\..\\..\\windows\\win.ini",       # backslash variant
    "/etc/passwd",                        # absolute path
    "....//....//etc/passwd",             # nested-dot bypass
]

# Markers proving a real system file leaked out of the root.
LEAK_MARKERS = ("root:x:", "root:", "[extensions]", "[fonts]")


@pytest.mark.parametrize("payload", TRAVERSAL)
def test_traversal_payload_rejected(client, user_a, payload):
    resp = client.get(FILE_ROUTE.format(name=payload), headers=user_a["headers"])
    # Rejected (400/404) — never 200 with out-of-root content.
    assert resp.status_code in (400, 404), (
        f"traversal {payload!r} returned {resp.status_code}; expected 400/404 "
        f"(canonicalize + confine to the allow-listed base dir)."
    )
    low = resp.text.lower()
    for marker in LEAK_MARKERS:
        assert marker.lower() not in low, f"FILE LEAK: {marker!r} escaped the root via {payload!r}"


def test_legit_in_root_file_still_served(client, user_a):
    """Over-correction guard: a normal in-root filename must still resolve."""
    resp = client.get(FILE_ROUTE.format(name=LEGIT_NAME), headers=user_a["headers"])
    assert resp.status_code == 200, f"in-root file blocked ({resp.status_code}) — guard is too broad"
