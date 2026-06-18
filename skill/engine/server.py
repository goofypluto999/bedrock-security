#!/usr/bin/env python3
"""
bedrock-security :: server.py — the local console (live UI + orchestration).

The application you imagined:
  1. runs locally               -> `python engine/server.py <target-repo>`
  2. opens a live UI            -> a browser dashboard the human watches + the AI drives
  3. AI walks EVERY check       -> /api/triage/stream emits one decision at a time, live
     one-by-one, green/red-lights    (green = applies to THIS project, red = N/A, amber = judgement)
  4. groups the green ones      -> the UI's approval panel: human ADD / REMOVE / approve
  5. final selection -> FULL run-> /api/run/stream proves each approved check, streamed live

It reuses the existing engine (sweep.py): the same Corpus walk, stack detection, and
per-check `evaluate()`. The server adds streaming + state + the human-approval gate.

Zero deps beyond PyYAML (already required by the registry). Stdlib http.server + SSE.

  python engine/server.py [TARGET_DIR] [--port 8765] [--no-open] [--run-commands]
"""
from __future__ import annotations

import argparse
import json
import sys
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

# Reuse the engine.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import yaml  # noqa: E402
from sweep import Corpus, detect_stacks, evaluate, SKILL_ROOT  # noqa: E402

STATE: dict = {
    "target": None,
    "stacks": [],
    "corpus": None,
    "checks": [],        # summarized check cards (static metadata for the UI)
    "results": {},       # id -> full evaluate() result
    "approved": [],       # ids the human approved for the full run
    "run_commands": False,
}


def summarize(check: dict) -> dict:
    """Build the dense, code-format card the UI shows for each check (few words, max context)."""
    ap = (check.get("applicability") or {})
    proof = (check.get("proof") or {})
    oracle = ", ".join(check.get("oracle", []))
    method = check.get("method", "?")
    q = (ap.get("question") or "").strip()
    pc = (check.get("pass_criteria") or "").strip()
    fa = (check.get("fail_action") or "").strip()
    desc = (proof.get("description") or "").strip().replace("\n", " ")
    if len(desc) > 220:
        desc = desc[:217] + "..."
    # almost-code summary block — title is the id; body is signature-like
    code = (
        f"{check['id']}  [{check.get('severity','?')}]  {check.get('domain','?')}/{check.get('phase','?')}\n"
        f"applies? {q}\n"
        f"prove({method}): {desc or pc}\n"
        f"PASS ⇔ {pc}\n"
        f"FAIL → {fa}"
    )
    return {
        "id": check["id"],
        "title": check.get("title", check["id"]),
        "domain": check.get("domain"),
        "phase": check.get("phase"),
        "severity": check.get("severity"),
        "method": method,
        "oracle": oracle,
        "summary": code,
        "templates": list(((proof.get("templates")) or {}).keys()),
    }


def load_registry() -> list[dict]:
    reg = yaml.safe_load((Path(__file__).with_name("registry.yaml")).read_text(encoding="utf-8"))
    return reg.get("checks", [])


def init_state(target: Path, run_commands: bool) -> None:
    checks = load_registry()
    STATE["target"] = str(target)
    STATE["corpus"] = Corpus(target)
    STATE["stacks"] = detect_stacks(STATE["corpus"])
    STATE["checks"] = [summarize(c) for c in checks]
    STATE["_raw"] = checks
    STATE["results"] = {}
    STATE["approved"] = []
    STATE["run_commands"] = run_commands


def triage_state(result: dict) -> str:
    """Map an evaluate() result to a UI triage light."""
    if result["applicable"] is True:
        return "green"      # applies to this project -> include in the run
    if result["applicable"] is False:
        return "red"        # proven N/A here
    return "amber"          # 'unknown' (manual probe) -> human/AI judgement; default-include


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):  # quiet
        pass

    # -- helpers --
    def _json(self, obj, code=200):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _sse_open(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.send_header("X-Accel-Buffering", "no")
        self.end_headers()

    def _sse(self, obj) -> bool:
        try:
            self.wfile.write(f"data: {json.dumps(obj)}\n\n".encode())
            self.wfile.flush()
            return True
        except (BrokenPipeError, ConnectionResetError, OSError):
            return False

    # -- routing --
    def do_GET(self):
        path = urlparse(self.path).path
        if path in ("/", "/index.html"):
            html = (SKILL_ROOT / "ui" / "index.html").read_text(encoding="utf-8")
            body = html.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif path == "/api/state":
            self._json({
                "target": STATE["target"],
                "stacks": STATE["stacks"],
                "checks": STATE["checks"],
                "run_commands": STATE["run_commands"],
                "total": len(STATE["checks"]),
            })
        elif path == "/api/triage/stream":
            self.stream_triage()
        elif path == "/api/run/stream":
            self.stream_run()
        else:
            self._json({"error": "not found"}, 404)

    def do_POST(self):
        path = urlparse(self.path).path
        if path == "/api/approve":
            n = int(self.headers.get("Content-Length", 0))
            data = json.loads(self.rfile.read(n) or b"{}")
            STATE["approved"] = list(data.get("approved", []))
            self._json({"ok": True, "approved": len(STATE["approved"])})
        else:
            self._json({"error": "not found"}, 404)

    # -- phase 1: triage (applicability), one check at a time, live --
    def stream_triage(self):
        self._sse_open()
        corpus, stacks = STATE["corpus"], STATE["stacks"]
        counts = {"green": 0, "red": 0, "amber": 0}
        for check in STATE["_raw"]:
            res = evaluate(check, corpus, stacks, STATE["run_commands"])
            STATE["results"][check["id"]] = res
            light = triage_state(res)
            counts[light] += 1
            ev = res.get("evidence") or []
            reason = res.get("note") or ""
            if not self._sse({
                "type": "triage", "id": check["id"], "light": light,
                "status": res["status"], "confidence": res["confidence"],
                "reason": reason,
                "evidence": [f"{e['file']}:{e['line']}" if e.get("line") else e["file"] for e in ev[:3]],
            }):
                return
            time.sleep(0.05)  # visible pacing — watch the AI work through each
        # default selection = everything that applies (green + amber); reds excluded
        preselect = [c["id"] for c in STATE["_raw"]
                     if triage_state(STATE["results"][c["id"]]) in ("green", "amber")]
        STATE["approved"] = preselect
        self._sse({"type": "done", "counts": counts, "preselect": preselect})

    # -- phase 2: full run over the approved set, live --
    def stream_run(self):
        self._sse_open()
        approved = set(STATE["approved"])
        ran = {"PASS": 0, "FAIL": 0, "NEEDS-PROOF": 0, "NA": 0}
        for check in STATE["_raw"]:
            if check["id"] not in approved:
                continue
            res = STATE["results"].get(check["id"]) or evaluate(check, STATE["corpus"], STATE["stacks"], STATE["run_commands"])
            ran[res["status"]] = ran.get(res["status"], 0) + 1
            tmpl = ((check.get("proof") or {}).get("templates") or {})
            if not self._sse({
                "type": "run", "id": check["id"], "status": res["status"],
                "method": check.get("method"), "severity": check.get("severity"),
                "reason": res.get("note") or "",
                "evidence": [f"{e['file']}:{e['line']}" if e.get("line") else e["file"]
                             for e in (res.get("evidence") or [])[:3]],
                "templates": tmpl,
                "fail_action": check.get("fail_action") or "",
            }):
                return
            time.sleep(0.06)
        green = ran["FAIL"] == 0 and ran["NEEDS-PROOF"] == 0
        self._sse({"type": "verdict", "counts": ran, "green": green,
                   "open": ran["FAIL"] + ran["NEEDS-PROOF"]})


def main() -> int:
    ap = argparse.ArgumentParser(description="bedrock-security local console")
    ap.add_argument("target", nargs="?", default=".")
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--no-open", action="store_true")
    ap.add_argument("--run-commands", action="store_true")
    args = ap.parse_args()

    target = Path(args.target).resolve()
    if not target.is_dir():
        sys.stderr.write(f"ERROR: not a directory: {target}\n")
        return 2

    init_state(target, args.run_commands)
    url = f"http://127.0.0.1:{args.port}/"
    print(f"bedrock-security console")
    print(f"  target : {target}")
    print(f"  stacks : {', '.join(STATE['stacks'])}")
    print(f"  checks : {len(STATE['checks'])}")
    print(f"  open   : {url}")
    if not args.no_open:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    srv = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
