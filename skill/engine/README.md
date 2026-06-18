# engine/ — the sweep engine

The machinery that turns the playbook into an executed, evidence-backed sweep.

```
engine/
  registry.yaml   the single source of truth — every check as a structured record
  sweep.py        the runner — frames the surface, runs probes, emits the gated ledger
  README.md       this file
```

The skill's prose (`../references/*.md`) is the **depth**. `registry.yaml` is the
**enforceable index**. `sweep.py` **executes** it. `../PROTOCOL.md` is the **forced
procedure** a human/agent follows to close what the runner can't decide alone.

---

## Run it

```bash
python engine/sweep.py [TARGET_DIR] [--out DIR] [--run-commands] [--registry PATH] [--json-only]
```

- `TARGET_DIR` — repo to sweep (default `.`).
- `--out` — where to write the ledger (default `<target>/.bedrock/`).
- `--run-commands` — **opt-in**. Execute `command` probes (gitleaks, pip-audit,
  pytest, …). Off by default so nothing networked/billable/surprising runs without
  your say-so; without it, those checks become NEEDS-PROOF with the exact command printed.
- Exit code: **0 = GREEN** (every applicable check proven), **1 = RED** (open items
  remain), **2 = usage/env error**. The exit code is the CI gate.

Outputs `LEDGER.md` (human) and `ledger.json` (machine) in the out dir.

Dependency: `pip install pyyaml`. Everything else is Python stdlib.

## The console (live local app)

```bash
python engine/server.py [TARGET_DIR] [--port 8765] [--no-open] [--run-commands]
```

`server.py` reuses this engine and adds a **live UI** (`../ui/index.html`, served at
`http://127.0.0.1:8765/`) plus a human-approval gate — the two-phase flow:

1. **Triage** (`/api/triage/stream`, SSE) — walks every check one at a time, live:
   green = applies · red = N/A · amber = judgement (each with file:line evidence).
2. **Approve** (`/api/approve`) — the UI groups the applicable+judgement set with
   ADD/REMOVE checkboxes; you approve the final selection.
3. **Run** (`/api/run/stream`, SSE) — proves the approved set, streaming PASS / FAIL /
   NEEDS-PROOF (with the proof-template path) per check, then the gated verdict.

Same `registry.yaml`, same `evaluate()`, same gate as the headless runner — the
console is just the watch-it-happen surface over it. Stdlib `http.server` + SSE; the
only dependency is still PyYAML.

---

## The check record schema

Each entry under `checks:` in `registry.yaml`:

```yaml
- id: BOLA-001                      # stable unique id (DOMAIN-NNN)
  title: <one line>
  domain: access-control           # cluster (see meta.domains)
  phase: adversarial               # frame | static | adversarial | decision | triage
  severity: critical               # critical | high | medium | low | info
  method: adversarial-test         # inventory | static-scan | adversarial-test | decision
  oracle: [OWASP API1:2023, CWE-639]   # external authority the check enforces
  applicability:
    question: <when does this apply?>
    auto_probe:                    # how the runner decides applicability/result
      type: grep_present           # grep_present | antipattern | file_present | command | manual
      patterns: ['<regex>', ...]   # for grep/antipattern (Python re; use \x27 for a literal ')
      langs: [py, ts, js, sql]     # restrict probe to these languages (optional)
  proof:
    description: <how to PROVE it — the adversarial test or the live probe>
    templates:                     # runnable proof per stack (for adversarial-test)
      python-fastapi: templates/python-fastapi/test_bola.py
      typescript-node: templates/typescript-node/bola.test.ts
      supabase-postgres: templates/supabase-postgres/bola_rls.sql
  pass_criteria: <the falsifiable bar for PASS>
  fail_action: <what a FAIL means + the fix direction>
  ref: references/hardening-playbook.md#1    # depth pointer (or skill://<other-skill>)
```

### auto_probe types (what `sweep.py` does with each)

| type | runner behaviour |
|---|---|
| `grep_present` | patterns found ⇒ surface EXISTS ⇒ **APPLICABLE** (then NEEDS-PROOF unless trivially static). None found ⇒ **N/A** (auto-low; confirm if unsure). |
| `antipattern` | patterns found ⇒ **FAIL** (evidence = the matching `file:line`s). None found ⇒ **PASS** (auto-low; absence-of-evidence). |
| `file_present` | glob(s) exist ⇒ **PASS** (or `also_grep` checks contents); missing ⇒ **FAIL**. For `method: inventory` it's detection-only (informational). |
| `command` | with `--run-commands`: run it, exit 0 ⇒ PASS, non-zero ⇒ FAIL. Without: NEEDS-PROOF + prints the command. Tool missing ⇒ `absent_status`. |
| `manual` | runner can't decide ⇒ **NEEDS-PROOF**; the agent/human closes it per PROTOCOL.md. |

`patterns` for `grep_present`/`antipattern` are **Python regex** (searched over file
contents). `patterns` for `file_present` are **globs** (matched against paths). To
match a literal single quote inside a YAML single-quoted string, use `\x27` (writing
a real `'` would close the YAML string).

---

## Confidence levels in the ledger

- `auto` — the runner ran a deterministic probe/command and is confident.
- `auto-low` — absence-of-evidence (a clean antipattern grep, or no surface signal).
  Strong but not infinite; a strict sweep re-confirms these by reading the code.
- `agent` — the runner deferred; a human/agent must attach the proof.

---

## Extending the registry

Append a new record (e.g. from a security tip in a video — see `../MEDIA-INTAKE.md`),
then **always re-validate**:

```bash
python -c "import yaml; yaml.safe_load(open('engine/registry.yaml',encoding='utf-8')); print('registry OK')"
python engine/sweep.py .   # smoke-run so a bad pattern/record surfaces immediately
```

A new adversarial check should ship with at least one stack template (or be marked
QUEUED in `templates/INDEX.md` — never silently template-less).
