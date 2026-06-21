"""
LLM-OUT-001 — LLM output scrub masks secrets and PII (OWASP LLM02:2025 / LLM06:2025, CWE-532).

PROVE: when the model's response contains secrets or PII (an API key, an AWS access key, a
bearer/JWT, an email, a credit-card-shaped number), the value is MASKED before it returns to
the user. Clean output with no sensitive tokens is returned UNTOUCHED. The same scrubber that
guards logs must guard model output (single source of truth) — so a planted secret never
reaches the client or the log sink verbatim.

This is a falsifiable, oracle-anchored test: it forces the model to emit planted secrets and
asserts they are masked. Wire the TODOs (a route whose model reply you can seed).
"""
import pytest

LLM_ROUTE = "/api/assistant"              # TODO: a route that returns model text
INPUT_FIELD = "prompt"                    # TODO: the user-text field name

# TODO: the import path of the function/fixture that sets the next model completion,
#       so we can plant a known string into the model's OUTPUT deterministically.
PLANT_TARGET = "app.llm.client.complete"

# Synthetic secret-SHAPED fixtures, ASSEMBLED at runtime from fragments so no
# key-shaped literal lives in source — a public-repo secret scanner flags a literal
# even when it is fake. These are inputs that exercise the scrubber, never real
# credentials; the assembled runtime value still matches real secret formats.
SECRETS = [
    ("openai_key", "sk-" + "Synthetic0Fixture0NotARealKey0000000000000"),
    ("aws_key", "AKIA" + "SYNTHETIC000FAKE"),
    ("bearer", "Bearer " + "eyJ" + "synthetichdr.eyJ" + "fixturepayload.sig"),
    ("email", "victim.user@example.com"),
    ("card", "4111 1111 1111 1111"),
]


@pytest.fixture
def model_says(monkeypatch):
    """Plant a fixed string as the model's completion. TODO: wire to your LLM client."""
    def _set(text: str):
        monkeypatch.setattr(PLANT_TARGET, lambda *a, **k: text, raising=False)
    return _set


@pytest.mark.parametrize("label,secret", SECRETS)
def test_planted_secret_is_masked(client, user_a, model_says, label, secret):
    model_says(f"Sure, here it is: {secret} — let me know if you need more.")
    resp = client.post(LLM_ROUTE, json={INPUT_FIELD: "give me the value"}, headers=user_a["headers"])
    assert resp.status_code == 200, resp.text[:200]
    assert secret not in resp.text, (
        f"{label} leaked verbatim in model output — apply scrub_output before returning text."
    )


def test_clean_output_untouched(client, user_a, model_says):
    """Over-correction guard: benign output must pass through byte-for-byte."""
    clean = "Your order ships Tuesday and the total is forty dollars."
    model_says(clean)
    resp = client.post(LLM_ROUTE, json={INPUT_FIELD: "status?"}, headers=user_a["headers"])
    assert resp.status_code == 200 and clean in resp.text, (
        "clean model output was altered — the scrubber is over-masking non-sensitive text."
    )
