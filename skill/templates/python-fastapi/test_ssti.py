"""
SSTI-001 — No server-side template injection on user input (CWE-1336, OWASP A03:2021).

PROVE: user input that lands in a template-rendered surface is treated as DATA, never as
template SOURCE. Classic probes — {{7*7}}, ${7*7}, #{7*7}, <%= 7*7 %> — must come back
LITERAL (the string "7*7" or escaped), never evaluated to "49". Evaluation means the engine
compiled attacker text and is one gadget away from RCE. User data must be passed as a
template variable, never concatenated into the template string.

This is a falsifiable, oracle-anchored test. It actively submits template-expression
payloads and asserts none are evaluated. Wire the TODOs.
"""
import pytest

# TODO: a route that reflects a field through a template engine (name → rendered greeting,
#   display name on a profile page, a subject line rendered into an email body, etc.).
RENDER_ROUTE = "/api/render"   # body: {"name": "..."} → renders into a template
FIELD = "name"

# (payload, the string that would appear if the engine EVALUATED it)
SSTI_PAYLOADS = [
    ("{{7*7}}", "49"),                       # Jinja2 / Twig / Nunjucks
    ("${7*7}", "49"),                        # JS template literal / Thymeleaf / FreeMarker
    ("#{7*7}", "49"),                        # Ruby / some EL dialects
    ("<%= 7*7 %>", "49"),                    # ERB / EJS
    ("{{7*'7'}}", "7777777"),                # Jinja2 string-multiply tell
    ("${{7*7}}", "49"),                      # nested / filter-bypass attempt
    ("{{config}}", "SECRET"),                # Jinja2 object exposure probe
]


@pytest.mark.parametrize("payload,evaluated", SSTI_PAYLOADS)
def test_template_expression_not_evaluated(client, user_a, payload, evaluated):
    resp = client.post(RENDER_ROUTE, json={FIELD: payload}, headers=user_a["headers"])
    assert resp.status_code in (200, 201, 400, 422), f"unexpected {resp.status_code}: {resp.text[:200]}"
    if resp.status_code in (200, 201):
        body = resp.text
        # The evaluated result must NOT appear; the literal payload (or its escaped form) should.
        assert evaluated not in body, (
            f"SSTI: {payload!r} evaluated to {evaluated!r} → template compiled from user input (CWE-1336)"
        )
        # Object/secret exposure tell for the {{config}} probe.
        assert "SECRET_KEY" not in body and "SQLALCHEMY" not in body, "SSTI exposed template globals"
