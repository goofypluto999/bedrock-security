"""
TIMING-001 — Submitted-secret comparisons are constant-time (CWE-208).

PROVE: every code path that compares an attacker-submittable secret (API key, reset token,
HMAC signature, TOTP) uses a constant-time primitive (hmac.compare_digest), never Python's
`==`/`!=`, which short-circuits on the first differing byte and leaks the secret one
character at a time via response timing. We assert the CALL by code inspection — timing
assertions are flaky in CI, so we prove the primitive is used and the `==` anti-pattern is
absent rather than measuring nanoseconds.

This is a falsifiable, oracle-anchored test. Wire the TODOs (the modules that verify secrets).
"""
import ast
import inspect
import re

import pytest

# TODO: import the real modules/functions that compare submitted secrets.
# from app.auth import verify_api_key, verify_reset_token
# from app.webhooks import verify_signature
SECRET_VERIFIERS = [
    # verify_api_key,
    # verify_reset_token,
    # verify_signature,
]

CONSTANT_TIME = ("compare_digest", "timingSafeEqual", "ConstantTimeCompare")
# names that look like an attacker-submittable secret being compared with ==/!=
SECRET_NAME = re.compile(r"(token|api_?key|secret|hmac|signature|sig|totp|otp|digest)", re.I)


@pytest.mark.parametrize("fn", SECRET_VERIFIERS)
def test_secret_verifier_uses_constant_time_primitive(fn):
    src = inspect.getsource(fn)
    assert any(p in src for p in CONSTANT_TIME), (
        f"{fn.__name__} compares a secret without a constant-time primitive "
        f"(expected one of {CONSTANT_TIME}) → timing oracle (CWE-208)"
    )


@pytest.mark.parametrize("fn", SECRET_VERIFIERS)
def test_secret_verifier_has_no_naive_equality(fn):
    """No `==`/`!=` where either operand is a secret-shaped name (the leaking anti-pattern)."""
    tree = ast.parse(inspect.getsource(fn).lstrip())
    for node in ast.walk(tree):
        if isinstance(node, ast.Compare) and any(
            isinstance(op, (ast.Eq, ast.NotEq)) for op in node.ops
        ):
            operands = [node.left, *node.comparators]
            names = [n.id for n in operands if isinstance(n, ast.Name)]
            names += [n.attr for n in operands if isinstance(n, ast.Attribute)]
            leaking = [n for n in names if SECRET_NAME.search(n)]
            assert not leaking, (
                f"{fn.__name__} uses ==/!= on secret-shaped operand(s) {leaking} "
                f"→ replace with hmac.compare_digest over equal-length hashes"
            )
