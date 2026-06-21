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
from sweep import (  # noqa: E402
    Corpus, detect_stacks, evaluate, SKILL_ROOT, load_dag, dag_for, blocked_result,
)
import graphlib  # noqa: E402

STATE: dict = {
    "target": None,
    "stacks": [],
    "corpus": None,
    "checks": [],        # summarized check cards (static metadata for the UI)
    "results": {},       # id -> full evaluate() result
    "approved": [],       # ids the human approved for the full run
    "run_commands": False,
    "env": "all",         # Phase D: environment rail (all/pre-commit/ci/preview/staging/prod)
    "dag_map": {},        # id -> merged dag overlay (requires/environments/safety/...)
    "order": [],          # topological check-id order
}


STAGES = ["0 · Scope & Safety", "1 · Frame & Inventory", "2 · Static",
          "3 · Dynamic-Passive", "4 · Dynamic-Adversarial", "5 · LLM / AI",
          "6 · Decision & Verdict"]


def stage_of(check: dict, meta: dict) -> str:
    """Map a check to one of the 7 council stages (phase + domain + env-safety)."""
    cid = check["id"]
    phase = check.get("phase")
    dom = check.get("domain")
    envs = meta.get("environments", [])
    safety = meta.get("safety", {})
    if cid in ("SCOPE-001", "DATA-SAFETY-001", "INV-007", "DEPLOY-GATE-001"):
        return STAGES[0]
    if phase == "frame":
        return STAGES[1]
    if phase == "static":
        return STAGES[2]
    if dom == "llm-ai":
        return STAGES[5]
    if phase == "adversarial":
        passive = "preview" in envs and not (safety.get("destructive") or safety.get("needs_seed_data"))
        return STAGES[3] if passive else STAGES[4]
    if phase in ("decision", "triage"):
        return STAGES[6]
    return STAGES[2]


def summarize(check: dict, meta: dict) -> dict:
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
        "stage": stage_of(check, meta),
        "requires": meta.get("requires", []),
        "environments": meta.get("environments", []),
        "safety": meta.get("safety", {}),
    }


def load_registry() -> list[dict]:
    reg = yaml.safe_load((Path(__file__).with_name("registry.yaml")).read_text(encoding="utf-8"))
    return reg.get("checks", [])


def init_state(target: Path, run_commands: bool, env: str = "all") -> None:
    checks = load_registry()
    dag = load_dag(Path(__file__).with_name("dag.yaml"))
    by_id = {c["id"]: c for c in checks}
    dag_map = {cid: dag_for(cid, dag) for cid in by_id}
    graph = {cid: {r for r in dag_map[cid]["requires"] if r in by_id} for cid in by_id}
    try:
        order = list(graphlib.TopologicalSorter(graph).static_order())
    except graphlib.CycleError:
        order = list(by_id)
    STATE["target"] = str(target)
    STATE["corpus"] = Corpus(target)
    STATE["stacks"] = detect_stacks(STATE["corpus"])
    STATE["_raw"] = checks
    STATE["_by_id"] = by_id
    STATE["dag_map"] = dag_map
    STATE["order"] = order
    STATE["checks"] = [summarize(by_id[cid], dag_map[cid]) for cid in order]  # cards in topo order
    STATE["results"] = {}
    STATE["approved"] = []
    STATE["run_commands"] = run_commands
    STATE["env"] = env


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

    def _qs_env(self) -> str:
        from urllib.parse import parse_qs
        return parse_qs(urlparse(self.path).query).get("env", [STATE["env"]])[0]

    @staticmethod
    def _next_action(counts: dict) -> str:
        if counts.get("amber"):
            return "Review the judgement calls below, then approve the selection."
        if counts.get("green"):
            return "Approve the applicable set and run the proofs."
        if counts.get("blocked"):
            return "Switch the environment (top-right) to run the blocked stages — e.g. staging."
        return "Clean floor — nothing applies to this surface."

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
                "env": STATE["env"],
                "envs": ["all", "pre-commit", "ci", "preview", "staging", "prod"],
                "stages": STAGES,
                "total": len(STATE["checks"]),
            })
        elif path == "/api/assets":
            try:
                import assets as _a
                self._json(_a.build_assets(list(STATE["results"].values()), STATE["stacks"], STATE["target"]))
            except Exception as e:  # pragma: no cover
                self._json({"error": str(e)}, 500)
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

    # -- phase 1: triage (applicability), DAG-ordered, env-aware, one at a time --
    def stream_triage(self):
        self._sse_open()
        env = self._qs_env()
        STATE["env"] = env
        corpus, stacks = STATE["corpus"], STATE["stacks"]
        counts = {"green": 0, "red": 0, "amber": 0, "blocked": 0}
        for cid in STATE["order"]:
            check, meta = STATE["_by_id"][cid], STATE["dag_map"][cid]
            stage = stage_of(check, meta)
            if env != "all" and env not in meta["environments"]:
                STATE["results"][cid] = blocked_result(check, meta, "env rail")
                counts["blocked"] += 1
                ok = self._sse({"type": "triage", "id": cid, "light": "blocked", "stage": stage,
                                "status": "BLOCKED",
                                "reason": f"runs in {'/'.join(meta['environments'])}, not env={env}",
                                "evidence": []})
                if not ok:
                    return
                time.sleep(0.02)
                continue
            res = evaluate(check, corpus, stacks, STATE["run_commands"])
            STATE["results"][cid] = res
            light = triage_state(res)
            counts[light] += 1
            ev = res.get("evidence") or []
            if not self._sse({
                "type": "triage", "id": cid, "light": light, "stage": stage,
                "status": res["status"], "confidence": res["confidence"],
                "reason": res.get("note") or "",
                "evidence": [f"{e['file']}:{e['line']}" if e.get("line") else e["file"] for e in ev[:3]],
            }):
                return
            time.sleep(0.04)
        preselect = [cid for cid in STATE["order"]
                     if STATE["results"][cid]["status"] != "BLOCKED"
                     and triage_state(STATE["results"][cid]) in ("green", "amber")]
        STATE["approved"] = preselect
        self._sse({"type": "done", "counts": counts, "preselect": preselect,
                   "next_action": self._next_action(counts), "env": env})

    # -- phase 2: full run over the approved set, DAG-ordered with BLOCKED propagation --
    def stream_run(self):
        self._sse_open()
        env = self._qs_env()
        approved = set(STATE["approved"])
        ran = {"PASS": 0, "FAIL": 0, "NEEDS-PROOF": 0, "NA": 0, "BLOCKED": 0}
        done: dict = {}
        for cid in STATE["order"]:
            if cid not in approved:
                continue
            check, meta = STATE["_by_id"][cid], STATE["dag_map"][cid]
            stage = stage_of(check, meta)
            if env != "all" and env not in meta["environments"]:
                res = blocked_result(check, meta, f"env: runs in {'/'.join(meta['environments'])}, not {env}")
            else:
                block = None
                for req in meta["requires"]:
                    pr = done.get(req) or STATE["results"].get(req)
                    if pr and pr["status"] == "BLOCKED":
                        block = f"{req} BLOCKED"; break
                    if pr and pr["status"] == "FAIL" and STATE["dag_map"].get(req, {}).get("blocks_if_fail"):
                        block = f"{req} FAILED"; break
                if block:
                    res = blocked_result(check, meta, f"dep: requires {block}")
                else:
                    res = STATE["results"].get(cid) or evaluate(check, STATE["corpus"], STATE["stacks"], STATE["run_commands"])
            done[cid] = res
            ran[res["status"]] = ran.get(res["status"], 0) + 1
            tmpl = ((check.get("proof") or {}).get("templates") or {})
            if not self._sse({
                "type": "run", "id": cid, "status": res["status"], "stage": stage,
                "method": check.get("method"), "severity": check.get("severity"),
                "reason": res.get("note") or "",
                "evidence": [f"{e['file']}:{e['line']}" if e.get("line") else e["file"]
                             for e in (res.get("evidence") or [])[:3]],
                "templates": tmpl,
                "fail_action": check.get("fail_action") or "",
            }):
                return
            time.sleep(0.05)
        green = ran["FAIL"] == 0 and ran["NEEDS-PROOF"] == 0
        self._sse({"type": "verdict", "counts": ran, "green": green,
                   "open": ran["FAIL"] + ran["NEEDS-PROOF"], "blocked": ran["BLOCKED"]})


def main() -> int:
    ap = argparse.ArgumentParser(description="bedrock-security local console")
    ap.add_argument("target", nargs="?", default=".")
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--no-open", action="store_true")
    ap.add_argument("--run-commands", action="store_true")
    ap.add_argument("--env", default="all",
                    choices=["all", "pre-commit", "ci", "preview", "staging", "prod"],
                    help="default environment rail (the UI can switch it live)")
    args = ap.parse_args()

    target = Path(args.target).resolve()
    if not target.is_dir():
        sys.stderr.write(f"ERROR: not a directory: {target}\n")
        return 2

    init_state(target, args.run_commands, args.env)
    url = f"http://127.0.0.1:{args.port}/"
    print(f"bedrock-security console")
    print(f"  target : {target}")
    print(f"  stacks : {', '.join(STATE['stacks'])}")
    print(f"  checks : {len(STATE['checks'])}")
    print(f"  env    : {args.env}")
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
