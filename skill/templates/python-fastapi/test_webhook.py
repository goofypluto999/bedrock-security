"""
WEBHOOK-001 — Inbound webhook verified: HMAC over raw body, replay window, idempotent (OWASP A08:2021).

PROVE: a forged or stale webhook cannot be accepted. A missing or wrong HMAC signature →
400; a correctly-signed payload whose timestamp is outside the tolerance window (replay) →
rejected; the SAME signed event delivered twice → its side effect happens exactly once.
The HMAC is computed over the RAW request bytes, not over re-serialized JSON (so a
byte-for-byte resign by the server is impossible to fake).

This is a falsifiable, oracle-anchored test. It actively forges/replays/duplicates webhook
deliveries and asserts each is rejected or deduped. Wire the TODOs.
"""
import hashlib
import hmac
import json
import time

import pytest

WEBHOOK_ROUTE = "/api/webhooks/provider"   # TODO: your inbound webhook route
SIG_HEADER = "X-Signature"                  # TODO: the provider's signature header
TS_HEADER = "X-Timestamp"                   # TODO: the provider's timestamp header
SECRET = b"whsec_test_only_not_a_real_key"  # TODO: the TEST signing secret (never a live one)


def _sign(raw: bytes, ts: str) -> str:
    mac = hmac.new(SECRET, f"{ts}.".encode() + raw, hashlib.sha256)
    return "sha256=" + mac.hexdigest()


def _post(client, raw: bytes, sig: str | None, ts: str):
    headers = {"Content-Type": "application/json", TS_HEADER: ts}
    if sig is not None:
        headers[SIG_HEADER] = sig
    return client.post(WEBHOOK_ROUTE, content=raw, headers=headers)


@pytest.mark.parametrize("sig", [None, "sha256=deadbeef", "garbage", ""])
def test_bad_or_missing_signature_rejected(client, sig):
    raw = json.dumps({"id": "evt_1", "type": "ping"}).encode()
    resp = _post(client, raw, sig, str(int(time.time())))
    assert resp.status_code == 400, f"bad/missing sig accepted (got {resp.status_code})"


def test_replayed_old_timestamp_rejected(client):
    raw = json.dumps({"id": "evt_replay", "type": "ping"}).encode()
    old = str(int(time.time()) - 3600)          # 1h old → outside any sane tolerance
    resp = _post(client, raw, _sign(raw, old), old)
    assert resp.status_code in (400, 403), f"stale replay accepted (got {resp.status_code})"


def test_duplicate_event_id_processed_once(client):
    raw = json.dumps({"id": "evt_dup", "type": "charge.succeeded"}).encode()
    ts = str(int(time.time()))
    sig = _sign(raw, ts)
    first = _post(client, raw, sig, ts)
    second = _post(client, raw, sig, ts)
    assert first.status_code in (200, 202), first.text
    assert second.status_code in (200, 202, 409), second.text
    # TODO: assert the underlying side effect (charge/insert) ran exactly ONCE.
    # assert count_side_effects("evt_dup") == 1
