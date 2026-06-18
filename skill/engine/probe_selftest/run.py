#!/usr/bin/env python3
"""
Probe regression self-test — guards the static probes against drift in BOTH directions.

Runs the sweep against two fixture trees in this directory:
  bad/   every WATCHED check MUST FAIL  (false-NEGATIVE guard — real vulns still caught)
  good/  the exact code shapes that have FALSE-fired before; NONE may FAIL
         (false-POSITIVE guard — no crying wolf)

These fixtures are the falsifiable record of every probe tightening. When you edit a
pattern in registry.yaml, run this; if BAD stops flagging something or GOOD starts
flagging something, you regressed.

    python engine/probe_selftest/run.py     # exit 0 = pass, 1 = regression

The `probe_selftest` directory is in sweep.py's IGNORE_DIRS, so these intentionally
"vulnerable" fixtures never contaminate a normal sweep of the skill itself.
"""
import json
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
SWEEP = HERE.parent / "sweep.py"
WATCH = [
    "PATTERN-001", "PATTERN-003", "PATTERN-004", "FLOOR-A02", "FLOOR-A05",
    "FLOOR-A08", "FLOOR-A09", "EXCESSDATA-001", "CLIENT-ENV-001",
]


def watched_fails(target: Path) -> set[str]:
    out = Path(tempfile.mkdtemp())
    subprocess.run(
        [sys.executable, str(SWEEP), str(target), "--out", str(out), "--json-only"],
        capture_output=True, text=True,
    )
    data = json.loads((out / "ledger.json").read_text(encoding="utf-8"))
    status = {r["id"]: r["status"] for r in data["results"]}
    return {w for w in WATCH if status.get(w) == "FAIL"}


def main() -> int:
    bad = watched_fails(HERE / "bad")
    good = watched_fails(HERE / "good")
    ok = True

    false_negatives = [w for w in WATCH if w not in bad]
    if false_negatives:
        ok = False
        print(f"FAIL (false negative): BAD did not flag {false_negatives}")
    if good:
        ok = False
        print(f"FAIL (false positive): GOOD wrongly flagged {sorted(good)}")

    if ok:
        print(f"PASS — BAD flags all {len(WATCH)} watched checks; GOOD flags none.")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
