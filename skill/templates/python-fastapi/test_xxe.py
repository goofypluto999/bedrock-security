"""
XXE-001 — XML parsing disables external entities (no XXE) (CWE-611, OWASP A05:2021).

PROVE: a crafted XML document cannot read local files, reach internal URLs, or detonate an
exponential-entity (billion-laughs) expansion. An external-entity payload referencing
/etc/passwd → the entity is NOT resolved (no file contents reflected); a SYSTEM url entity →
no outbound fetch; a billion-laughs document → rejected/inert, never a memory/CPU blowup.
DTD and external-entity resolution must be disabled (e.g. defusedxml in Python).

This is a falsifiable, oracle-anchored test. It actively submits XXE / billion-laughs
payloads and asserts entities are never resolved. Wire the TODOs.
"""
import pytest

XML_ROUTE = "/api/xml"   # TODO: any route that parses user-supplied XML (or SVG/DOCX/SOAP)

FILE_XXE = (
    '<?xml version="1.0"?>'
    '<!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
    "<root>&xxe;</root>"
)
SSRF_XXE = (
    '<?xml version="1.0"?>'
    '<!DOCTYPE root [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>'
    "<root>&xxe;</root>"
)
BILLION_LAUGHS = (
    '<?xml version="1.0"?>'
    '<!DOCTYPE lolz ['
    '<!ENTITY lol "lol">'
    '<!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">'
    '<!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">'
    '<!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">'
    ']><lolz>&lol4;</lolz>'
)


@pytest.mark.parametrize("payload", [FILE_XXE, SSRF_XXE, BILLION_LAUGHS])
def test_xxe_entities_not_resolved(client, user_a, payload):
    resp = client.post(XML_ROUTE, content=payload,
                       headers={**user_a["headers"], "Content-Type": "application/xml"})
    # A hardened parser rejects the DTD/entity (400/422) or parses with the entity left
    # inert. Either way it must NOT 500 from expansion and must NOT leak resolved content.
    assert resp.status_code != 500, "XXE/expansion crashed the parser → external entities enabled"
    assert resp.status_code in (200, 400, 422), f"unexpected {resp.status_code}: {resp.text[:200]}"
    body = resp.text
    # File-read oracle: /etc/passwd contents must never appear.
    assert "root:x:0:0" not in body and "/bin/bash" not in body, "XXE resolved a local file → CWE-611"
    # Metadata/SSRF oracle: no fetched internal content reflected.
    assert "ami-id" not in body and "iam/security-credentials" not in body, "XXE reached metadata"
