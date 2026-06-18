"""
JWT-001 — JWT decode rejects none/confusion/missing-exp/expired/tampered/aud (RFC 8725).

PROVE: six classes of abusive token are ALL rejected with 401 on a protected route:
(1) alg=none, (2) RS->HS confusion (re-sign with the RS256 PUBLIC key as an HMAC secret),
(3) missing-exp, (4) expired, (5) tampered-signature, (6) aud-mismatch. Do NOT trust the
library default for missing-exp — prove it with a token that has no exp claim. Falsifiable
failure: any crafted token below yields 200. The validator must pin the algorithm, require
exp, and validate aud/iss.

Wire the TODOs (a protected route, the HS secret, the RS keypair, expected aud/iss).
"""
import time
import pytest
import jwt  # PyJWT

PROTECTED_PATH = "/api/me"          # TODO: any route requiring a valid access token
HS_SECRET = "TODO-server-hmac-secret"
RS_PUBLIC_KEY = "TODO-PEM-public-key"   # the server's RS256 public key (attacker-known)
AUDIENCE = "marr-api"               # TODO: the server's expected aud
ISSUER = "marr-auth"                # TODO: the server's expected iss


def _send(client, token):
    return client.get(PROTECTED_PATH, headers={"Authorization": f"Bearer {token}"})


def _claims(**over):
    base = {"sub": "1", "aud": AUDIENCE, "iss": ISSUER, "exp": int(time.time()) + 3600}
    base.update(over)
    return base


def _crafted_tokens():
    """Yield (label, token) for each abuse class. Each MUST be rejected 401."""
    # 1. alg=none — unsigned token claiming no algorithm.
    yield "alg_none", jwt.encode(_claims(), key="", algorithm="none")
    # 2. RS->HS confusion: sign with HS256 using the PUBLIC key bytes as the secret.
    yield "rs_to_hs_confusion", jwt.encode(_claims(), key=RS_PUBLIC_KEY, algorithm="HS256")
    # 3. missing exp — library defaults often do NOT require it.
    no_exp = _claims(); no_exp.pop("exp")
    yield "missing_exp", jwt.encode(no_exp, key=HS_SECRET, algorithm="HS256")
    # 4. expired.
    yield "expired", jwt.encode(_claims(exp=int(time.time()) - 10), key=HS_SECRET, algorithm="HS256")
    # 5. tampered signature — flip the last char of a validly-signed token.
    good = jwt.encode(_claims(), key=HS_SECRET, algorithm="HS256")
    yield "tampered_sig", good[:-1] + ("A" if good[-1] != "A" else "B")
    # 6. audience mismatch.
    yield "aud_mismatch", jwt.encode(_claims(aud="some-other-service"), key=HS_SECRET, algorithm="HS256")


@pytest.mark.parametrize("label,token", list(_crafted_tokens()))
def test_abusive_token_rejected(client, label, token):
    resp = _send(client, token)
    assert resp.status_code == 401, (
        f"JWT abuse class '{label}' was ACCEPTED (got {resp.status_code}, expected 401). "
        f"Pin the alg allow-list, require exp, and validate aud/iss (RFC 8725)."
    )


def test_valid_token_still_accepted(client, user_a):
    """Over-correction guard: a properly-minted token from the app must still work."""
    assert _send(client, user_a["token"]).status_code == 200
