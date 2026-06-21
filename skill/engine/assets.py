"""
Phase B — the asset map (`.bedrock/assets.json`).

Stage-1 FRAME emits this file from the inventory checks' evidence; the adversarial
proof templates READ it (via a loader / the pytest `assets` fixture) instead of
hardcoding routes, tenants, and token types. It is the bridge from "the engine found
a surface" to "the test knows exactly what to attack".

Design:
- `detected_at` arrays are AUTO-populated from the INV checks' grep evidence (the
  file:line locations where routes / tokens / fetches / LLM surfaces / secrets live).
  That gives the agent (or a future deeper FRAME parser) a precise head-start map.
- `items` arrays are the ENRICHED specifics a test actually needs (the route list with
  auth/owner fields, the token-type names, the tenant object ids). FRAME / the agent
  fills these; templates that find them use them, else fall back to their TODO defaults.
- `secrets` carries NAMES ONLY, never values.

100% additive: nothing here changes how the existing sweep runs; it just writes one
extra file the templates can opt into.
"""
from __future__ import annotations

import json
from pathlib import Path

SCHEMA_VERSION = "assets/1"

# Which inventory check feeds which asset bucket.
INV_FEEDS = {
    "INV-001": "routes",
    "INV-002": "token_types",
    "INV-003": "external_fetches",
    "INV-004": "secrets",
    "INV-005": "tenant_resources",
    "INV-006": "llm_surfaces",
    "INV-007": "deploy_targets",
}


def _signals(by_id: dict, check_id: str) -> list[dict]:
    r = by_id.get(check_id) or {}
    out = []
    for e in (r.get("evidence") or []):
        if e.get("file") and not str(e.get("file")).startswith("..."):
            out.append({"file": e["file"], "line": e.get("line", 0)})
    return out


def build_assets(results: list[dict], stacks: list[str], target: str) -> dict:
    """Assemble the asset map from inventory-check evidence (auto-detected surfaces)."""
    by_id = {r["id"]: r for r in results}
    return {
        "schema": SCHEMA_VERSION,
        "target": target,
        "stacks": stacks,
        # tenants A/B — the identity convention every multi-tenant template targets.
        # FRAME/the seed fixture fills the ids; tokens come from these env-var NAMES.
        "tenants": {
            "A": {"id": None, "token_env": "BEDROCK_TOKEN_A"},
            "B": {"id": None, "token_env": "BEDROCK_TOKEN_B"},
        },
        # auto-detected surface locations (file:line); enrich `items` with the specifics.
        "routes":           {"detected_at": _signals(by_id, "INV-001"), "items": []},  # {method,path,auth_required,roles_allowed,owner_field}
        "roles":            {"items": []},                                             # {name, token_env, privileged}
        "token_types":      {"detected_at": _signals(by_id, "INV-002"), "items": []},  # {name, purpose, source}
        "tenant_resources": {"detected_at": _signals(by_id, "INV-005"), "items": []},  # {type, table, owner_field, route, test_object_a_id, test_object_b_id}
        "external_fetches": {"detected_at": _signals(by_id, "INV-003"), "items": []},  # {source, url_pattern, user_controlled}
        "webhooks":         {"items": []},                                             # {provider, path, secret_env}
        "llm_surfaces":     {"detected_at": _signals(by_id, "INV-006"), "items": []},  # {surface, user_input_reaches_prompt, tools_exposed, tool_has_fetch_url, has_rag}
        "datastores":       {"detected_at": _signals(by_id, "INV-005"), "items": []},  # {type, supabase_project, rls_enabled}
        "secrets":          {"detected_at": _signals(by_id, "INV-004"), "items": []},  # {name, exposed_client}  -- NAMES ONLY
        "deploy_targets":   {"detected_at": _signals(by_id, "INV-007"), "items": []},  # {platform, url, confirmed_owned, rollback_command}
    }


def write_assets(out_dir: Path, assets: dict) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    p = out_dir / "assets.json"
    p.write_text(json.dumps(assets, indent=2), encoding="utf-8")
    return p


def load_assets(start: Path | None = None) -> dict:
    """Find + load `.bedrock/assets.json`, walking up from `start` (default cwd). {} if absent."""
    start = (start or Path.cwd()).resolve()
    for d in [start, *start.parents]:
        c = d / ".bedrock" / "assets.json"
        if c.exists():
            try:
                return json.loads(c.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                return {}
    return {}
