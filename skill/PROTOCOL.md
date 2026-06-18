# The Bedrock Security Sweep — Driver Protocol

> This is the **forced procedure**. The reference docs tell you *what* to check
> and *why*; this file makes you actually *do it*, **in order**, and **prove** each
> result instead of claiming it. If you are running a security sweep, audit,
> hardening pass, or "is this secure?" review, you run THIS, top to bottom. You do
> not freestyle. You do not declare "secure" until the gate in §7 passes.

---

## 0. Prime directive — PROVE, don't claim

A claim is "I checked X, it's fine." **That is not allowed here.** Every applicable
check resolves to one of exactly three states, each backed by an **artifact**:

| State | What it means | The artifact that proves it |
|---|---|---|
| **PASS** | The control is present AND correct | A passing adversarial test, a probe response, a command exit, or a cited `file:line` that demonstrably implements it |
| **FAIL** | The control is absent or broken | The failing test, the grep hit, the probe that got through, the `file:line` of the bug |
| **N/A** | The check genuinely does not apply to THIS project | The probe/enumeration that shows the surface is absent (e.g. "no JWT minting anywhere: grep returned nothing across N files") |

A check with **no artifact yet** is **NEEDS-PROOF**. NEEDS-PROOF is not a verdict —
it is a debt. The sweep is not done while any applicable check is NEEDS-PROOF.

> "I verified it" is a claim. "Here is the test that tries to break it and fails to"
> is proof. We deal only in proof.

---

## 1. The non-negotiable order

Run the stages in this exact sequence. Each depends on the one before it.

```
Stage 0  FRAME         enumerate the attack surface (routes, auth, fetches, secrets, stores, LLM, deploy)
Stage 1  APPLICABILITY for EVERY registry check: does it apply here? prove yes/no
Stage 2  STATIC        run every static-scan probe; capture evidence; auto-PASS/FAIL what is decidable
Stage 3  ADVERSARIAL   author + run a falsifiable test for every applicable adversarial check
Stage 4  DECISION      record the forced decisions (fail-open/closed, kill-switch, CSRF posture)
Stage 5  TRIAGE        classify every FAIL into Class 1-5; fix Class 1/2, document 3/4/5
Stage 6  VERDICT       regenerate the ledger; apply the gate (§7); only now may you speak
```

Why this order (it mirrors `hardening-playbook.md §9` — cheap/most-likely-to-reject
first, expensive/irreversible last): you cannot test authz on routes you have not
enumerated (0→1), you should not hand-write an adversarial test for a surface a
cheap grep proves absent (1→2→3), and you must not triage failures you have not yet
produced (3→5).

---

## 2. Per-stage operating instructions

### Stage 0 — FRAME
Run the engine to bootstrap the surface map, then complete the inventory checks
(`INV-001 … INV-008`) by hand where the runner marks them NEEDS-PROOF. Produce, as
written artifacts: the route table, the token-type list, the outbound-fetch list,
the secret/env name list (NAMES ONLY — never values), the tenancy model, the LLM
surface list, and the confirmed deploy target. **You cannot audit what you have not
enumerated.**

### Stage 1 — APPLICABILITY
The runner auto-decides applicability where it can (grep/file probes) and marks the
rest `manual`. For every `manual` and every `auto-low` N/A, **you** make the call —
with evidence. "Not applicable" is a finding that must be *proven* (the absent
surface), never a default you reach for to skip work. When uncertain, it applies.

### Stage 2 — STATIC
The runner executes these. For `command` probes (secret-scan, dep-audit, test-suite)
it will only run them if invoked with `--run-commands`; otherwise it hands you the
exact command and you run it and paste the evidence. Do not let a missing scanner
become a silent skip — install it or run an equivalent and record that.

### Stage 3 — ADVERSARIAL
For each applicable adversarial check, open its proof template (`templates/<stack>/…`
named in the registry record), adapt it to the real routes/models from Stage 0, and
**run it against the real system**. The test must be *falsifiable* and
*oracle-anchored* (cite the OWASP/CWE/RFC id in the test). A test that only asserts
the happy path is not proof — see `security-testing-methodology.md §1`. Prefer
**isolation authorship**: where possible, write the test from the contract + the
oracle WITHOUT reading the implementation's internal justifications.

### Stage 4 — DECISION
Some controls are not proven by a test but by a **recorded decision**: every
control's fail-open/closed choice (`DEC-001`), an env kill-switch for every blocking
control (`DEC-002`), and the CSRF posture matching the auth transport (`CSRF-001`).
Write the decision next to the control in code, and in the ledger. An accidental
fail-mode is a latent incident.

### Stage 5 — TRIAGE
Every FAIL gets a class (§5) before you touch code. Fix Class 1/2. Document Class
3/4/5. Record each in `tests/security/TRIAGE.md`. "12 failing" is noise; "1 Class-1,
3 Class-3, 8 Class-4" is a plan.

### Stage 6 — VERDICT
Re-run the engine so the ledger reflects every artifact you produced. Apply the gate
(§7). The ledger (`.bedrock/LEDGER.md`) is the deliverable — not your prose summary.

---

## 3. The evidence standard (what counts, per method)

- **inventory** → a written enumeration artifact (table/list) in the ledger or a note.
- **static-scan** → the runner's captured grep/file/command output, OR a `file:line`
  you cite and the reviewer can open.
- **adversarial-test** → a test file that runs red-before / green-after (or green
  proving the defense holds), with the oracle cited in the docstring, **passing in a
  clean batch run** (not just in isolation — `TEST-ISO-001`).
- **decision** → the documented choice (fail-open/closed + kill-switch + rationale),
  visible in code and ledger.

If you cannot produce the artifact, the check stays NEEDS-PROOF. You may not upgrade
it to PASS by reasoning about it.

---

## 4. Status rules + the gate

- Default every applicable check to **NEEDS-PROOF**.
- Move to PASS/FAIL/N-A **only** with the artifact §3 requires.
- A grep/`auto-low` PASS or N/A (absence-of-evidence) is provisional. On a **strict
  sweep**, re-confirm every `auto-low` by reading the relevant code, not just trusting
  the absent pattern.
- **The gate (the enforcement):** the sweep is **RED** while *any* applicable check
  is FAIL or NEEDS-PROOF. `sweep.py` returns **exit code 1** in that state. GREEN —
  and the right to say "this is secure for the scoped surface" — requires every
  applicable check at PASS or proven-N/A. There is no partial credit and no "good
  enough, ship it" override inside the protocol; that override is a **human** decision
  made *explicitly and on the record*, never an agent's default.

---

## 5. Triage taxonomy (classify every FAIL before fixing)

1. **Class 1 — Real product vulnerability.** Attacker can do the bad thing. Fix code. Highest priority.
2. **Class 2 — Real, lower severity / defense-in-depth gap.** Fix or consciously accept + document.
3. **Class 3 — Environment-only.** Repros only under a test shortcut (SQLite-ism, no real concurrency). Document; do NOT weaken the code to make it pass.
4. **Class 4 — Invalid spec.** The test encodes a wrong assumption. Fix the test, not the code.
5. **Class 5 — Platform/infra limit.** Postgres-only/Redis-only/multi-worker-only; can't be exercised here. Mark; verify in staging.

(Full detail: `security-testing-methodology.md §3`.)

---

## 6. Cross-checking — mandatory, both directions

- A "**control X is missing**" finding may be a **stale doc**, not the live code.
  **Verify every "missing" claim against the current code** before acting. (In a real
  audit, four "unimplemented" flags were all actually shipped — read from stale notes.)
- A "**✅ present**" claim must cite the `file:line` and confirm it is wired on
  **every** relevant route, not one.
- When you fix a control, **update or delete the doc/docstring that called it broken
  in the same change** (`DOC-FRESH-001`). A stale "expected-fail" docstring is how a
  real red flag gets "fixed" to green without fixing the product.

---

## 7. Completion bar — do not say "secure" until ALL of these hold

- [ ] Stages 0–6 were run in order; the route/token/fetch/secret inventories exist.
- [ ] Every registry check is APPLICABLE-with-a-verdict or proven-N/A — none left NEEDS-PROOF.
- [ ] Every PASS has an attached artifact (test / probe / command / `file:line`).
- [ ] Every FAIL has a triage class and is fixed (1/2) or documented (3/4/5).
- [ ] The adversarial suite passes in a **clean batch run** AND randomized order (`TEST-ISO-001`).
- [ ] Fail-open/closed + kill-switch decisions are recorded for every control (`DEC-001/002`).
- [ ] `sweep.py` exits **0** (GREEN) for the scoped surface — or any remaining open
      item is an explicit, on-the-record **human** acceptance, not an agent shortcut.
- [ ] No stale doc describes a shipped control as missing (`DOC-FRESH-001`).

---

## 8. Quick start

```bash
# 1) Frame + applicability + static proofs + ledger (no commands run):
python engine/sweep.py /path/to/target

# 2) Same, but also execute scanner commands (gitleaks, pip-audit, pytest):
python engine/sweep.py /path/to/target --run-commands

# 3) Read the open items, then close each:
#    .bedrock/LEDGER.md   (human)   ·   .bedrock/ledger.json   (machine)

# 4) For each OPEN adversarial check, copy its template, wire it to the real
#    routes from Stage 0, run it, fix to green, re-run sweep until exit 0.
```

The runner does the deterministic floor and frames the rest; **you** (driven by this
protocol) close the judgment checks with real tests. Neither half is optional.
