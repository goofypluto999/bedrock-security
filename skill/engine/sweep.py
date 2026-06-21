#!/usr/bin/env python3
"""
bedrock-security :: sweep.py — the enforcement runner.

Turns the prose playbook into an executed, evidence-backed sweep. It:

  Stage 0  FRAME        detect stack(s); count attack-surface signals
  Stage 1  APPLICABILITY for every registry check: applies here? prove yes/no
  Stage 2  STATIC        run the probes the runner CAN execute itself, with evidence
  Stage 3+ HAND-OFF      mark adversarial/decision/inventory checks NEEDS-PROOF so the
                         agent (driven by PROTOCOL.md) MUST close each with an artifact

Then it writes a verdict ledger (ledger.json + LEDGER.md) and GATES the result:
a sweep is GREEN only if every APPLICABLE check is PASS or proven-NA. Any FAIL or
NEEDS-PROOF -> RED, exit code 1. That gate is the whole point: nothing is skipped,
and "secure" cannot be claimed while an applicable check is unproven.

Design choices that matter:
  * Command-running probes (gitleaks, pip-audit, pytest) are OPT-IN via --run-commands.
    Without it they become NEEDS-PROOF with the exact command printed for you to run.
    Nothing billable, networked, or surprising runs by default.
  * A clean antipattern grep is treated as auto-PASS (confidence: auto) — strong but
    not infinite evidence; the protocol re-confirms low-confidence autos on a strict sweep.
  * The runner NEVER prints secret VALUES; antipattern evidence is the matching code line,
    which for secret-format checks is itself sensitive — review the ledger before sharing.

Usage:
  python sweep.py [TARGET_DIR] [--out DIR] [--run-commands] [--registry PATH] [--json-only]

Dependency: PyYAML (pip install pyyaml). Everything else is stdlib.
"""
from __future__ import annotations

import argparse
import graphlib
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

try:
    import yaml
except ImportError:
    sys.stderr.write(
        "ERROR: PyYAML is required to read the registry.\n"
        "       Install it with:  pip install pyyaml\n"
    )
    sys.exit(2)

try:
    import assets as _assets  # Phase B: emit/read .bedrock/assets.json (additive)
except Exception:
    _assets = None

try:
    import report as _report  # the polished HTML audit report (additive)
except Exception:
    _report = None

# --------------------------------------------------------------------------- #
# Repo walking
# --------------------------------------------------------------------------- #

IGNORE_DIRS = {
    ".git", "node_modules", ".venv", "venv", "env", "dist", "build", ".next",
    "__pycache__", ".bedrock", "coverage", ".turbo", ".cache", "vendor",
    "target", ".mypy_cache", ".pytest_cache", ".idea", ".vscode", "out",
    ".claude", "worktrees", ".worktrees",  # agent/IDE worktree copies — not the real tree
    "probe_selftest",  # bedrock's own FP/FN regression fixtures — intentionally "vulnerable"
}
EXT_LANG = {
    ".py": "py",
    ".ts": "ts", ".tsx": "ts",
    ".js": "js", ".jsx": "js", ".mjs": "js", ".cjs": "js",
    ".sql": "sql",
    ".yml": "yaml", ".yaml": "yaml",
    ".toml": "toml",
    ".md": "md",
}
MAX_FILE_BYTES = 2_000_000
MAX_EVIDENCE = 6  # matches recorded per check before "+N more"


class Corpus:
    """In-memory snapshot of the target repo's text files, walked once."""

    def __init__(self, root: Path):
        self.root = root
        self.files: list[tuple[Path, str, str]] = []  # (path, lang, text)
        self.langs: set[str] = set()
        self._walk()

    def _walk(self) -> None:
        for dirpath, dirnames, filenames in os.walk(self.root):
            dirnames[:] = [d for d in dirnames if d not in IGNORE_DIRS]
            for name in filenames:
                ext = Path(name).suffix.lower()
                lang = EXT_LANG.get(ext)
                if not lang:
                    continue
                p = Path(dirpath) / name
                try:
                    if p.stat().st_size > MAX_FILE_BYTES:
                        continue
                    text = p.read_text(encoding="utf-8", errors="ignore")
                except OSError:
                    continue
                self.files.append((p, lang, text))
                self.langs.add(lang)

    def search(self, patterns: list[str], langs: list[str] | None) -> list[dict]:
        """Return match evidence: [{file, line, text}] across matching files."""
        compiled = []
        for pat in patterns:
            try:
                compiled.append(re.compile(pat, re.MULTILINE))
            except re.error:
                # A malformed registry pattern shouldn't crash the sweep.
                compiled.append(None)
        hits: list[dict] = []
        for path, lang, text in self.files:
            if langs and lang not in langs:
                continue
            for rx in compiled:
                if rx is None:
                    continue
                for m in rx.finditer(text):
                    line_no = text.count("\n", 0, m.start()) + 1
                    line = text.splitlines()[line_no - 1].strip() if text else ""
                    hits.append({
                        "file": str(path.relative_to(self.root)).replace("\\", "/"),
                        "line": line_no,
                        "text": line[:160],
                    })
        return hits

    def glob_present(self, patterns: list[str]) -> list[str]:
        found = []
        for pat in patterns:
            for match in self.root.glob(pat):
                rel = str(match.relative_to(self.root)).replace("\\", "/")
                if not any(part in IGNORE_DIRS for part in Path(rel).parts):
                    found.append(rel)
        return sorted(set(found))


# --------------------------------------------------------------------------- #
# Probe evaluation -> a per-check result
# --------------------------------------------------------------------------- #

STACK_SIGNALS = {
    "python-fastapi": ["fastapi", "uvicorn", "pydantic", "requirements.txt", "pyproject.toml"],
    "typescript-node": ["package.json", "tsconfig.json", "next.config", "express", "fastify"],
    "supabase-postgres": ["supabase", "migrations", ".sql"],
}


def detect_stacks(corpus: Corpus) -> list[str]:
    stacks = []
    names = " ".join(str(p).lower() for p, _, _ in corpus.files)
    blob = names + " " + " ".join(t.lower()[:2000] for _, _, t in corpus.files[:400])
    for stack, sigs in STACK_SIGNALS.items():
        if any(s in blob for s in sigs):
            stacks.append(stack)
    return stacks or ["unknown"]


def _trim(hits: list[dict]) -> list[dict]:
    if len(hits) <= MAX_EVIDENCE:
        return hits
    out = hits[:MAX_EVIDENCE]
    out.append({"file": f"... +{len(hits) - MAX_EVIDENCE} more matches", "line": 0, "text": ""})
    return out


def evaluate(check: dict, corpus: Corpus, stacks: list[str], run_commands: bool) -> dict:
    probe = (check.get("applicability") or {}).get("auto_probe") or {}
    ptype = probe.get("type", "manual")
    method = check.get("method", "manual")
    langs = probe.get("langs")

    res = {
        "id": check["id"],
        "title": check["title"],
        "domain": check.get("domain"),
        "phase": check.get("phase"),
        "severity": check.get("severity"),
        "method": method,
        "oracle": check.get("oracle", []),
        "ref": check.get("ref"),
        "fail_action": check.get("fail_action"),
        "applicable": None,      # True / False / "unknown"
        "status": "NEEDS-PROOF",  # PASS / FAIL / NA / NEEDS-PROOF
        "confidence": "auto",
        "evidence": [],
        "templates": {},
        "note": "",
    }

    # Attach proof templates (and whether they've been authored yet).
    templates = ((check.get("proof") or {}).get("templates")) or {}
    for stack, tmpl in templates.items():
        exists = (corpus.root / tmpl).exists() or (SKILL_ROOT / tmpl).exists()
        relevant = stack in stacks or "unknown" in stacks
        res["templates"][stack] = {
            "path": tmpl, "authored": bool(exists), "relevant_to_target": relevant,
        }

    # --- probe dispatch ---------------------------------------------------- #
    if ptype == "manual":
        res["applicable"] = "unknown"
        res["status"] = "NEEDS-PROOF"
        res["confidence"] = "agent"
        res["note"] = "Runner cannot decide. Agent must determine applicability and attach proof."

    elif ptype == "grep_present":
        hits = corpus.search(probe.get("patterns", []), langs)
        if hits:
            res["applicable"] = True
            res["evidence"] = _trim(hits)
            # Presence proves the surface EXISTS, not that it is correct.
            if method in ("adversarial-test", "inventory", "decision"):
                res["status"] = "NEEDS-PROOF"
                res["confidence"] = "agent"
                res["note"] = "Surface present -> applicable. Proof still required (see method/template)."
            else:  # static-scan grep_present (e.g. HDR-001) -> attempt present, verify required
                res["status"] = "NEEDS-PROOF"
                res["confidence"] = "agent"
                res["note"] = "Control attempt present -> verify it is correct/complete (live probe)."
        else:
            res["applicable"] = False
            res["status"] = "NA"
            res["confidence"] = "auto-low"
            res["note"] = "No surface signals found. Confirm truly N/A if uncertain."

    elif ptype == "antipattern":
        hits = corpus.search(probe.get("patterns", []), langs)
        if hits:
            res["applicable"] = True
            res["status"] = "FAIL"
            res["confidence"] = "auto"
            res["evidence"] = _trim(hits)
            res["note"] = "Known-bad pattern detected. Triage (Class 1-5) then fix."
        else:
            res["applicable"] = True
            res["status"] = "PASS"
            res["confidence"] = "auto-low"
            res["note"] = "No known-bad pattern found (absence-of-evidence; confirm on strict sweep)."

    elif ptype == "file_present":
        found = corpus.glob_present(probe.get("patterns", []))
        also = probe.get("also_grep")
        if method == "inventory":
            # Detection only (e.g. stack detect) — informational, never fails.
            res["applicable"] = bool(found)
            res["status"] = "NA" if not found else "NEEDS-PROOF"
            res["evidence"] = [{"file": f, "line": 0, "text": ""} for f in found]
            res["confidence"] = "auto"
            res["note"] = "Detection probe (informational)."
        elif found:
            res["applicable"] = True
            res["evidence"] = [{"file": f, "line": 0, "text": ""} for f in found]
            if also:
                blob = ""
                for _f in found:
                    try:
                        blob += (corpus.root / _f).read_text(encoding="utf-8", errors="ignore")
                    except OSError:
                        pass
                missing = [a for a in also if not re.search(a, blob)]
                if missing:
                    res["status"] = "FAIL"
                    res["confidence"] = "auto"
                    res["note"] = f"File present but missing expected entries: {missing}"
                else:
                    res["status"] = "PASS"
                    res["confidence"] = "auto"
                    res["note"] = "File present with expected entries."
            else:
                res["status"] = "PASS"
                res["confidence"] = "auto"
        else:
            res["applicable"] = True
            res["status"] = "FAIL"
            res["confidence"] = "auto"
            res["note"] = f"Required file(s) not found: {probe.get('patterns')}"

    elif ptype == "command":
        cmd = probe.get("command", "")
        absent_status = probe.get("absent_status", "NEEDS-PROOF")
        res["applicable"] = True
        if not run_commands:
            res["status"] = "NEEDS-PROOF"
            res["confidence"] = "agent"
            res["note"] = f"Command probe (opt-in). Run with --run-commands, or run manually: `{cmd}`"
        else:
            outcome = run_command_probe(cmd, corpus.root, probe.get("fallback_command"))
            if outcome is None:
                res["status"] = absent_status
                res["confidence"] = "agent"
                res["note"] = f"Scanner tool not available. Install it or prove equivalently: `{cmd}`"
            else:
                ok, tail = outcome
                res["status"] = "PASS" if ok else "FAIL"
                res["confidence"] = "auto"
                res["evidence"] = [{"file": "(command output)", "line": 0, "text": tail[:600]}]
                res["note"] = f"Ran: `{cmd}`"
    else:
        res["note"] = f"Unknown probe type '{ptype}'."

    return res


def run_command_probe(cmd: str, cwd: Path, fallback: str | None):
    """Return (ok: bool, output_tail: str) or None if no scanner tool exists."""
    for c in [cmd, fallback]:
        if not c:
            continue
        tool = re.split(r"\s|\|", c.strip())[0]
        # crude availability check: is the first token resolvable?
        from shutil import which
        if which(tool) is None and "&&" not in c and "||" not in c:
            continue
        try:
            proc = subprocess.run(
                c, cwd=str(cwd), shell=True, capture_output=True,
                text=True, timeout=300,
            )
            out = (proc.stdout or "") + (proc.stderr or "")
            return (proc.returncode == 0, out[-1200:])
        except (subprocess.TimeoutExpired, OSError):
            return None
    return None


# --------------------------------------------------------------------------- #
# DAG + safety overlay (Phase A) — ordering, BLOCKED propagation, env rails
# --------------------------------------------------------------------------- #

DEFAULT_ENVS = ["pre-commit", "ci", "preview", "staging", "prod"]
DEFAULT_SAFETY = {"destructive": False, "cost_generating": False, "needs_seed_data": False,
                  "readonly": True, "safe_in_prod": True, "external_side_effect": False}


def load_dag(path: Path) -> dict:
    """Load the DAG/safety overlay; absent file -> empty (pure back-compat)."""
    if not path.exists():
        return {"defaults": {}, "checks": {}}
    d = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return {"defaults": d.get("defaults") or {}, "checks": d.get("checks") or {}}


def dag_for(check_id: str, dag: dict) -> dict:
    """Merge defaults + per-check overlay for one check id (omitted fields -> safe defaults)."""
    out = {"requires": [], "provides": [], "blocks_if_fail": False,
           "environments": list(DEFAULT_ENVS), "safety": dict(DEFAULT_SAFETY)}
    for layer in (dag.get("defaults") or {}, (dag.get("checks") or {}).get(check_id) or {}):
        for k, v in layer.items():
            if k == "safety" and isinstance(v, dict):
                out["safety"].update(v)
            else:
                out[k] = v
    return out


def blocked_result(check: dict, meta: dict, reason: str) -> dict:
    """A result skeleton for a check that never ran (env- or dependency-BLOCKED)."""
    return {
        "id": check["id"], "title": check.get("title", check["id"]),
        "domain": check.get("domain"), "phase": check.get("phase"),
        "severity": check.get("severity"), "method": check.get("method"),
        "oracle": check.get("oracle", []), "ref": check.get("ref"),
        "fail_action": check.get("fail_action"), "applicable": "unknown",
        "status": "BLOCKED", "confidence": "n/a", "evidence": [], "templates": {},
        "note": reason, "requires": meta["requires"],
        "environments": meta["environments"], "safety": meta["safety"],
    }


# --------------------------------------------------------------------------- #
# Ledger rendering
# --------------------------------------------------------------------------- #

STATUS_ORDER = {"FAIL": 0, "NEEDS-PROOF": 1, "BLOCKED": 2, "NA": 3, "PASS": 4}
STACK_LABEL = {"FAIL": "[FAIL]", "NEEDS-PROOF": "[OPEN]", "BLOCKED": "[BLOK]",
               "NA": "[N/A ]", "PASS": "[PASS]"}


def render_markdown(results: list[dict], stacks: list[str], root: Path, green: bool) -> str:
    counts = {s: 0 for s in STATUS_ORDER}
    for r in results:
        counts[r["status"]] = counts.get(r["status"], 0) + 1
    applicable_open = [r for r in results if r["status"] in ("FAIL", "NEEDS-PROOF")]

    lines = []
    lines.append("# Bedrock Security — Sweep Ledger\n")
    lines.append(f"- Target: `{root}`")
    lines.append(f"- Stack(s) detected: {', '.join(stacks)}")
    lines.append(f"- Verdict: **{'GREEN — all applicable checks proven' if green else 'RED — applicable checks remain open'}**")
    lines.append(
        f"- Tally: FAIL {counts.get('FAIL',0)} · OPEN {counts.get('NEEDS-PROOF',0)} · "
        f"BLOCKED {counts.get('BLOCKED',0)} · N/A {counts.get('NA',0)} · PASS {counts.get('PASS',0)} "
        f"(of {len(results)} checks)\n"
    )
    if not green:
        lines.append("> A GREEN verdict is impossible while any applicable check is FAIL or OPEN.")
        lines.append("> Close every OPEN item with an evidence artifact; triage every FAIL to a class.\n")

    for status in sorted(counts, key=lambda s: STATUS_ORDER[s]):
        group = [r for r in results if r["status"] == status]
        if not group:
            continue
        lines.append(f"\n## {STACK_LABEL[status]} {status} — {len(group)}\n")
        group.sort(key=lambda r: (str(r.get("severity")), r["id"]))
        for r in group:
            lines.append(f"### {r['id']} — {r['title']}")
            lines.append(
                f"`{r['domain']}` · phase `{r['phase']}` · severity **{r['severity']}** · "
                f"method `{r['method']}` · confidence `{r['confidence']}`"
            )
            if r["oracle"]:
                lines.append(f"Oracle: {', '.join(r['oracle'])}")
            if r["note"]:
                lines.append(f"Note: {r['note']}")
            if r["evidence"]:
                lines.append("Evidence:")
                for e in r["evidence"]:
                    loc = f"{e['file']}:{e['line']}" if e["line"] else e["file"]
                    snippet = f" — `{e['text']}`" if e["text"] else ""
                    lines.append(f"  - {loc}{snippet}")
            tmpls = r.get("templates") or {}
            if tmpls:
                shown = []
                for stack, info in tmpls.items():
                    flag = "authored" if info["authored"] else "QUEUED (not yet written)"
                    shown.append(f"{stack}: `{info['path']}` ({flag})")
                lines.append("Proof template(s): " + "; ".join(shown))
            if r["status"] in ("FAIL", "NEEDS-PROOF") and r.get("fail_action"):
                lines.append(f"Action: {r['fail_action']}")
            if r["ref"]:
                lines.append(f"Depth: {r['ref']}")
            lines.append("")
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #

SKILL_ROOT = Path(__file__).resolve().parent.parent  # .../skills/bedrock-security


def main() -> int:
    ap = argparse.ArgumentParser(description="Bedrock Security sweep runner")
    ap.add_argument("target", nargs="?", default=".", help="target repo dir (default: .)")
    ap.add_argument("--out", default=None, help="output dir (default: <target>/.bedrock)")
    ap.add_argument("--registry", default=str(Path(__file__).with_name("registry.yaml")))
    ap.add_argument("--run-commands", action="store_true",
                    help="opt-in: execute command probes (gitleaks, pip-audit, pytest, ...)")
    ap.add_argument("--env", default="all",
                    choices=["all", "pre-commit", "ci", "preview", "staging", "prod"],
                    help="enforce environment safety rails; 'all' (default) runs every check (back-compat)")
    ap.add_argument("--json-only", action="store_true", help="suppress stdout summary")
    args = ap.parse_args()

    root = Path(args.target).resolve()
    if not root.is_dir():
        sys.stderr.write(f"ERROR: target is not a directory: {root}\n")
        return 2

    reg = yaml.safe_load(Path(args.registry).read_text(encoding="utf-8"))
    checks = reg.get("checks", [])

    corpus = Corpus(root)
    stacks = detect_stacks(corpus)

    # --- Phase A: DAG-ordered evaluation with BLOCKED propagation + env rails ---
    dag = load_dag(Path(args.registry).with_name("dag.yaml"))
    by_id = {c["id"]: c for c in checks}
    dag_map = {cid: dag_for(cid, dag) for cid in by_id}
    graph = {cid: {r for r in dag_map[cid]["requires"] if r in by_id} for cid in by_id}
    try:
        order = list(graphlib.TopologicalSorter(graph).static_order())
    except graphlib.CycleError:
        order = list(by_id)  # defensive: fall back to registry order

    done: dict[str, dict] = {}
    for cid in order:
        check, meta = by_id[cid], dag_map[cid]
        # env rail: a check may only run in the selected environment
        if args.env != "all" and args.env not in meta["environments"]:
            done[cid] = blocked_result(check, meta,
                f"BLOCKED(env): runs in {'/'.join(meta['environments'])}, not --env={args.env}")
            continue
        # dependency rail: a required check that FAILed (with blocks_if_fail) or is BLOCKED blocks this one
        block = None
        for req in meta["requires"]:
            pr = done.get(req)
            if pr is None:
                continue
            if pr["status"] == "BLOCKED":
                block = f"{req} is BLOCKED"; break
            if pr["status"] == "FAIL" and dag_map[req]["blocks_if_fail"]:
                block = f"{req} FAILED"; break
        if block:
            done[cid] = blocked_result(check, meta, f"BLOCKED(dep): requires {block}")
            continue
        res = evaluate(check, corpus, stacks, args.run_commands)
        res["requires"] = meta["requires"]
        res["environments"] = meta["environments"]
        res["safety"] = meta["safety"]
        res["expected"] = check.get("pass_criteria")   # evidence schema: observed (evidence) vs expected
        done[cid] = res

    results = [done[c["id"]] for c in checks]  # preserve registry order in the ledger

    # The gate: GREEN only if no applicable check is FAIL or NEEDS-PROOF.
    # BLOCKED is "couldn't run here" (dep unmet or wrong --env) — deferred, not failing.
    open_items = [r for r in results if r["status"] in ("FAIL", "NEEDS-PROOF")]
    blocked_items = [r for r in results if r["status"] == "BLOCKED"]
    green = len(open_items) == 0

    out_dir = Path(args.out) if args.out else (root / ".bedrock")
    out_dir.mkdir(parents=True, exist_ok=True)
    ledger = {
        "target": str(root),
        "stacks": stacks,
        "env": args.env,
        "registry_version": reg.get("meta", {}).get("registry_version"),
        "generated_unix": int(time.time()),
        "verdict": "GREEN" if green else "RED",
        "total": len(results),
        "open": len(open_items),
        "blocked": len(blocked_items),
        "results": results,
    }
    (out_dir / "ledger.json").write_text(json.dumps(ledger, indent=2), encoding="utf-8")
    (out_dir / "LEDGER.md").write_text(render_markdown(results, stacks, root, green), encoding="utf-8")

    # Phase B: Stage-1 FRAME emits the asset map the adversarial templates consume.
    if _assets is not None:
        _assets.write_assets(out_dir, _assets.build_assets(results, stacks, str(root)))
    # The polished HTML audit report — every run ends with an openable report, not a text wall.
    if _report is not None:
        (out_dir / "report.html").write_text(_report.build_report_html(ledger), encoding="utf-8")

    if not args.json_only:
        c = {s: sum(1 for r in results if r["status"] == s) for s in STATUS_ORDER}
        print(f"\nBedrock sweep :: {root}")
        print(f"  stack(s): {', '.join(stacks)}   env: {args.env}")
        print(f"  FAIL {c['FAIL']}  OPEN {c['NEEDS-PROOF']}  BLOCKED {c['BLOCKED']}  N/A {c['NA']}  PASS {c['PASS']}  (of {len(results)})")
        print(f"  ledger : {out_dir / 'LEDGER.md'}")
        print(f"  REPORT : {out_dir / 'report.html'}   <- open this in a browser")
        verdict = "GREEN — all applicable checks proven" if green else "RED — applicable checks remain OPEN"
        print(f"  VERDICT: {verdict}")
        if not green:
            print("\n  Open items the agent/you must close with evidence (PROTOCOL.md):")
            for r in sorted(open_items, key=lambda r: (STATUS_ORDER[r["status"]], str(r["severity"]))):
                print(f"    {STACK_LABEL[r['status']]} {r['id']:<16} {r['severity']:<8} {r['title']}")
        if blocked_items:
            print(f"\n  {len(blocked_items)} BLOCKED (unmet deps or wrong --env) — see ledger; re-run with the right --env.")

    return 0 if green else 1


if __name__ == "__main__":
    raise SystemExit(main())
