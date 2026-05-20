# Contributing to Bedrock Security

Thanks for wanting to make this sharper. Bedrock has a deliberately high, narrow
bar — it's the *second-order* layer, not another OWASP summary.

## The bar for any addition

A contribution earns its place only if it is all three:

1. **Non-generic.** It goes *beyond* the checklist. If a generic security guide or
   an off-the-shelf AI assistant already surfaces it reliably (TLS, bcrypt,
   "validate input", the OWASP Top 10 definitions), it doesn't belong here. We
   document the failure mode people hit *after* they've done the obvious thing.
2. **Falsifiable.** It can be expressed as a test that tries to *break* the system,
   not one that confirms it works. State the adversarial test.
3. **Oracle-anchored.** Cite the authority that defines "correct" — an OWASP entry,
   an RFC clause, or a CWE id. If you can't name the oracle, you may be encoding an
   assumption.

## Format

Each control follows: **failure mode → fix → oracle → test**. Keep it concrete and
language-agnostic; pseudocode over framework-specific code unless the framework
detail *is* the point (e.g. the `require_exp` / `ProxyFix` knobs).

## What we especially want

- New second-order failure modes from real incidents (sanitized — no secrets, no
  proprietary detail).
- Corrections. If something here is wrong or oversimplified, open an issue with the
  authoritative reference and we'll fix it fast. Accuracy beats everything.
- Framework-specific "the knob is actually called X and the default is wrong"
  notes for the controls that are easy to misconfigure.

## What we'll decline

- Generic restatements of the basics.
- Tool advertisements / vendor pitches without a transferable principle.
- Anything that can't cite why it's "correct."

## Process

1. Open an issue describing the failure mode + the oracle before a large PR.
2. Keep PRs focused — one control or one correction.
3. No secrets, credentials, internal hostnames, or proprietary system details in
   examples. Everything must be generic and safe to publish.

By contributing you agree your work is licensed under the repository's
[MIT License](LICENSE).
