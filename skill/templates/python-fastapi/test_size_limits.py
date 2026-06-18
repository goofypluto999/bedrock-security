"""
SIZE-001 — Body size, JSON depth, and decompressed size are bounded (CWE-400).

PROVE: resource-exhaustion inputs are rejected cleanly, never crash the worker. An oversized
request body → 413; a pathologically deep nested-JSON document → 400 (a clean reject, NOT a
500 from blowing the recursion limit); a gzip "bomb" (tiny compressed, huge decompressed) →
capped on the DECOMPRESSED size before it is fully expanded into memory.

This is a falsifiable, oracle-anchored test. It actively sends oversized / over-deep /
over-expanding payloads and asserts each is bounded. Wire the TODOs.
"""
import gzip
import json

import pytest

BODY_ROUTE = "/api/objects"       # TODO: any route that accepts a JSON body
GZIP_ROUTE = "/api/import"        # TODO: a route that accepts gzip-encoded bodies
MAX_BYTES = 1 * 1024 * 1024       # TODO: your configured max body size


def test_oversized_body_rejected_413(client, user_a):
    huge = {"blob": "A" * (MAX_BYTES + 1024)}
    resp = client.post(BODY_ROUTE, json=huge, headers=user_a["headers"])
    assert resp.status_code == 413, f"oversized body not capped (got {resp.status_code})"


@pytest.mark.parametrize("depth", [200, 5000])
def test_over_deep_json_is_400_not_500(client, user_a, depth):
    # Build a deeply nested object: {"a":{"a":{...}}} — must reject, must NOT crash.
    nested = "{" + '"a":' * depth + "1" + "}" * depth
    resp = client.post(BODY_ROUTE, content=nested,
                       headers={**user_a["headers"], "Content-Type": "application/json"})
    assert resp.status_code != 500, f"depth {depth} crashed the parser (500) → unbounded recursion"
    assert resp.status_code in (400, 413, 422), f"depth {depth} not rejected cleanly: {resp.status_code}"


def test_gzip_bomb_capped_on_decompressed_size(client, user_a):
    """A tiny gzip payload that expands hugely must be capped on DECOMPRESSED bytes."""
    bomb = gzip.compress(b"A" * (50 * 1024 * 1024))   # ~50MB in, ~50KB on the wire
    assert len(bomb) < MAX_BYTES, "test bomb must slip past the raw-body limit to test decompression"
    resp = client.post(GZIP_ROUTE, content=bomb,
                       headers={**user_a["headers"],
                                "Content-Encoding": "gzip", "Content-Type": "application/json"})
    assert resp.status_code in (400, 413), (
        f"gzip bomb not capped on decompressed size (got {resp.status_code}) "
        f"→ decompress with a hard output-byte limit, never fully expand untrusted input"
    )
    assert resp.status_code != 500, "decompression OOM/crash → cap before expanding"
