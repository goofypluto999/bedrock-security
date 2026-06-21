#!/usr/bin/env python3
"""
report.py — render a polished, self-contained HTML AUDIT REPORT from a ledger.

The sweep and the console both call this, so every run ends with a real, openable
report (`.bedrock/report.html`) — not a wall of text. Dark, styled, inline-SVG charts,
findings grouped by status with severity + evidence + the fix action, stage progress,
and a decision-ready next-actions panel. Zero external dependencies (pure stdlib).
"""
from __future__ import annotations

import html
import time

STATUS_COLOR = {"FAIL": "#f85149", "NEEDS-PROOF": "#bc8cff", "BLOCKED": "#8b97a7",
                "NA": "#5b677a", "PASS": "#3fb950"}
STATUS_LABEL = {"FAIL": "FAIL", "NEEDS-PROOF": "Needs proof", "BLOCKED": "Blocked",
                "NA": "N/A", "PASS": "Pass"}
SEV_COLOR = {"critical": "#f85149", "high": "#d6a019", "medium": "#58a6ff",
             "low": "#8b97a7", "info": "#5b677a"}
ORDER = ["FAIL", "NEEDS-PROOF", "BLOCKED", "NA", "PASS"]


def _e(s) -> str:
    return html.escape(str(s if s is not None else ""))


def _stacked(counts: dict, width: int = 680, height: int = 26) -> str:
    total = sum(counts.values()) or 1
    x = 0.0
    segs = []
    for st in ORDER:
        n = counts.get(st, 0)
        if not n:
            continue
        w = n / total * width
        segs.append(
            f'<rect x="{x:.1f}" y="0" width="{max(w-1,1):.1f}" height="{height}" rx="3" '
            f'fill="{STATUS_COLOR[st]}"><title>{STATUS_LABEL[st]}: {n}</title></rect>'
        )
        x += w
    return f'<svg width="{width}" height="{height}" viewBox="0 0 {width} {height}">{"".join(segs)}</svg>'


def _chip(label: str, n: int, color: str) -> str:
    return (f'<span class="chip"><b style="color:{color}">{n}</b> {_e(label)}</span>')


def _finding(r: dict) -> str:
    sev = (r.get("severity") or "info")
    sevc = SEV_COLOR.get(sev, "#5b677a")
    ev = r.get("evidence") or []
    ev_html = ""
    if ev:
        items = "".join(
            f'<li>{_e(e.get("file"))}{":" + str(e["line"]) if e.get("line") else ""}'
            f'{(" — <code>" + _e(e.get("text")) + "</code>") if e.get("text") else ""}</li>'
            for e in ev[:6]
        )
        ev_html = f'<ul class="ev">{items}</ul>'
    tmpls = r.get("templates") or {}
    tmpl_html = ""
    if tmpls and r.get("status") == "NEEDS-PROOF":
        paths = " · ".join(_e(p) for p in tmpls.values())
        tmpl_html = f'<div class="tmpl">Proof template(s): {paths}</div>'
    action = ""
    if r.get("status") in ("FAIL", "NEEDS-PROOF") and r.get("fail_action"):
        action = f'<div class="action">▸ {_e(r["fail_action"])}</div>'
    note = f'<div class="note">{_e(r.get("note"))}</div>' if r.get("note") else ""
    oracle = (", ".join(r.get("oracle", [])) if isinstance(r.get("oracle"), list) else r.get("oracle")) or ""
    return f"""<div class="finding {r.get('status')}">
      <div class="fh">
        <span class="fid">{_e(r['id'])}</span>
        <span class="sev" style="color:{sevc};border-color:{sevc}55">{_e(sev)}</span>
        <span class="dom">{_e(r.get('domain'))}</span>
        <span class="fstatus" style="color:{STATUS_COLOR.get(r.get('status'),'#888')}">{_e(STATUS_LABEL.get(r.get('status'), r.get('status')))}</span>
      </div>
      <div class="ftitle">{_e(r.get('title'))}</div>
      {f'<div class="oracle">{_e(oracle)}</div>' if oracle else ''}
      {note}{ev_html}{tmpl_html}{action}
    </div>"""


def build_report_html(ledger: dict) -> str:
    results = ledger.get("results", [])
    counts = {}
    sev_fail = {}
    domains = {}
    for r in results:
        counts[r["status"]] = counts.get(r["status"], 0) + 1
        d = r.get("domain") or "—"
        domains.setdefault(d, {}).setdefault(r["status"], 0)
        domains[d][r["status"]] = domains[d].get(r["status"], 0) + 1
        if r["status"] == "FAIL":
            s = r.get("severity") or "info"
            sev_fail[s] = sev_fail.get(s, 0) + 1

    green = ledger.get("verdict") == "GREEN"
    total = len(results)
    ts = ledger.get("generated_unix")
    when = time.strftime("%Y-%m-%d %H:%M", time.localtime(ts)) if ts else ""

    # findings: FAIL first, then NEEDS-PROOF; the rest summarised
    fails = [r for r in results if r["status"] == "FAIL"]
    needs = [r for r in results if r["status"] == "NEEDS-PROOF"]
    fails.sort(key=lambda r: (["critical", "high", "medium", "low", "info"].index(r.get("severity", "info")) if r.get("severity") in SEV_COLOR else 9, r["id"]))

    # next actions
    actions = []
    if counts.get("FAIL"):
        actions.append(f'<b style="color:#f85149">{counts["FAIL"]} FAIL</b> — triage each (real vs false positive) by reading the cited file:line, then fix Class-1/2.')
    if counts.get("NEEDS-PROOF"):
        actions.append(f'<b style="color:#bc8cff">{counts["NEEDS-PROOF"]} need proof</b> — wire each check\'s template to the real routes and run it, or record a decision.')
    if counts.get("BLOCKED"):
        actions.append(f'<b style="color:#8b97a7">{counts["BLOCKED"]} blocked</b> — switch the environment (e.g. <code>--env staging</code>) to run them.')
    if not actions:
        actions.append("Every applicable check is proven. Keep this report as the audit artifact.")

    dom_rows = ""
    for d, dc in sorted(domains.items(), key=lambda kv: -sum(kv[1].get(s, 0) for s in ("FAIL", "NEEDS-PROOF"))):
        cells = "".join(
            f'<td style="color:{STATUS_COLOR[s]}">{dc.get(s, 0) or ""}</td>' for s in ORDER
        )
        dom_rows += f"<tr><td class='dn'>{_e(d)}</td>{cells}</tr>"

    sev_html = " ".join(
        f'<span class="sevchip" style="color:{SEV_COLOR[s]};border-color:{SEV_COLOR[s]}55">{n} {s}</span>'
        for s, n in sorted(sev_fail.items(), key=lambda kv: ["critical", "high", "medium", "low", "info"].index(kv[0]))
    ) or '<span class="muted">no FAILs</span>'

    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Bedrock Security — Audit Report</title>
<style>
:root{{--bg:#0a0d14;--panel:#10151f;--line:#1d2533;--txt:#e6edf3;--dim:#8b97a7;--teal:#5eead4;
--mono:ui-monospace,Menlo,Consolas,monospace;--sans:system-ui,-apple-system,Segoe UI,Roboto,sans-serif}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--txt);font-family:var(--sans);font-size:14px;line-height:1.5}}
.wrap{{max-width:980px;margin:0 auto;padding:28px 22px 80px}}
h1{{font-size:20px;margin:0 0 2px}}h1 b{{color:var(--teal)}}
.sub{{color:var(--dim);font-family:var(--mono);font-size:12px;margin-bottom:18px}}
.verdict{{padding:16px 20px;border-radius:12px;border:1px solid var(--line);font-size:18px;font-weight:700;margin:16px 0 22px}}
.verdict.green{{background:#0d1f14;border-color:#1c3a22;color:#3fb950}}
.verdict.red{{background:#1a0f14;border-color:#3a1c22;color:#f85149}}
.bar{{margin:10px 0 6px}}.legend{{display:flex;gap:14px;flex-wrap:wrap;font-family:var(--mono);font-size:12px;color:var(--dim)}}
.chips{{display:flex;gap:10px;flex-wrap:wrap;margin:14px 0}}
.chip{{border:1px solid var(--line);border-radius:20px;padding:4px 12px;font-size:12px;font-family:var(--mono);color:var(--dim)}}
h2{{font-size:13px;text-transform:uppercase;letter-spacing:.6px;color:var(--dim);font-family:var(--mono);margin:28px 0 10px;border-bottom:1px solid var(--line);padding-bottom:6px}}
.actions{{background:var(--panel);border:1px solid var(--line);border-left:3px solid var(--teal);border-radius:10px;padding:14px 18px}}
.actions ol{{margin:0;padding-left:18px}}.actions li{{margin:5px 0}}
table{{width:100%;border-collapse:collapse;font-size:13px;font-family:var(--mono)}}
th,td{{text-align:right;padding:5px 8px;border-bottom:1px solid var(--line)}}th{{color:var(--dim);font-weight:600}}
td.dn,th.dn{{text-align:left;color:var(--txt)}}
.sevchip{{border:1px solid;border-radius:6px;padding:2px 8px;font-size:11px;font-family:var(--mono);margin-right:6px}}
.muted{{color:var(--dim)}}
.finding{{background:var(--panel);border:1px solid var(--line);border-left:3px solid var(--line);border-radius:9px;padding:12px 14px;margin:9px 0}}
.finding.FAIL{{border-left-color:#f85149}}.finding.NEEDS-PROOF{{border-left-color:#bc8cff}}
.fh{{display:flex;align-items:center;gap:9px;flex-wrap:wrap}}
.fid{{font-family:var(--mono);color:var(--teal);font-weight:600;font-size:12px}}
.sev{{border:1px solid;border-radius:5px;padding:1px 7px;font-size:10px;font-family:var(--mono);text-transform:uppercase}}
.dom{{font-family:var(--mono);font-size:11px;color:var(--dim)}}
.fstatus{{margin-left:auto;font-family:var(--mono);font-size:12px;font-weight:600}}
.ftitle{{font-weight:600;margin:7px 0 4px}}.oracle{{font-family:var(--mono);font-size:11px;color:var(--dim)}}
.note{{color:var(--dim);font-size:12.5px;margin-top:5px}}
.ev{{margin:7px 0 0;padding-left:18px;font-family:var(--mono);font-size:11px;color:var(--dim)}}
.ev code{{color:#c9d4e3}}.tmpl{{font-family:var(--mono);font-size:11px;color:#bc8cff;margin-top:6px}}
.action{{margin-top:7px;font-size:12.5px;color:#e6edf3}}
.foot{{margin-top:40px;color:var(--dim);font-size:11px;font-family:var(--mono);text-align:center}}
</style></head><body><div class="wrap">
<h1><b>BEDROCK</b> SECURITY — Audit Report</h1>
<div class="sub">{_e(ledger.get('target'))} · env: {_e(ledger.get('env','all'))} · {total} checks{(' · ' + when) if when else ''}</div>

<div class="verdict {'green' if green else 'red'}">
  {'✓ GREEN — every applicable check is proven for the scoped surface.' if green else f"✗ RED — {ledger.get('open',0)} applicable check(s) still need a verdict (FAIL or proof)."}
</div>

<div class="bar">{_stacked(counts)}</div>
<div class="legend">
  {''.join(f'<span style="color:{STATUS_COLOR[s]}">&#9632;</span> {STATUS_LABEL[s]} {counts.get(s,0)}' for s in ORDER if counts.get(s,0))}
</div>

<div class="chips">
  {_chip('checks', total, 'var(--teal)')}
  {_chip('FAIL', counts.get('FAIL',0), STATUS_COLOR['FAIL'])}
  {_chip('need proof', counts.get('NEEDS-PROOF',0), STATUS_COLOR['NEEDS-PROOF'])}
  {_chip('blocked', counts.get('BLOCKED',0), STATUS_COLOR['BLOCKED'])}
  {_chip('N/A', counts.get('NA',0), STATUS_COLOR['NA'])}
  {_chip('pass', counts.get('PASS',0), STATUS_COLOR['PASS'])}
</div>

<h2>What to do next</h2>
<div class="actions"><ol>{''.join(f'<li>{a}</li>' for a in actions)}</ol></div>

<h2>Failures by severity</h2>
<div>{sev_html}</div>

<h2>Coverage by domain</h2>
<table><thead><tr><th class="dn">domain</th>{''.join(f'<th>{STATUS_LABEL[s]}</th>' for s in ORDER)}</tr></thead>
<tbody>{dom_rows}</tbody></table>

{('<h2>Failures (' + str(len(fails)) + ')</h2>' + ''.join(_finding(r) for r in fails)) if fails else ''}
{('<h2>Needs proof (' + str(len(needs)) + ')</h2>' + ''.join(_finding(r) for r in needs)) if needs else ''}

<div class="foot">Generated by bedrock-security · the RED ledger is the gate — green requires every applicable check PASS or proven-N/A.</div>
</div></body></html>"""
