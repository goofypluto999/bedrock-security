# S2 — Tools, Software & Environments
## Bedrock-Security Elevation Blueprint — Squad Agent S2

> **Primary source of truth:** `council/03-synthesis.md` §4.
> This spec owns: the 4-tool mandatory core, the optional-adapter detection logic, the
> `strategy[]` degradation ladder for every tool-backed check domain, the `safety{}` flag
> schema + per-check values, the `--env` enforcement matrix, the 5-environment → check-id
> mapping, and the "explicitly NOT in core" exclusion list. It does NOT own stage ordering
> (S1) or the assets/ledger/UX data model (S3).

---

## 1. THE MANDATORY CORE — 4 tools, zero optional

Voice 3 verdict (binding): the runner must be fully executable with exactly these four
tool families present. Every other tool degrades gracefully.

| Slot | Tool family | Canonical install | What it covers |
|---|---|---|---|
| **C1** | **semgrep** | `pip install semgrep` or `brew install semgrep` | SAST, antipatterns, custom rules (secrets, RSC leaks, anon-key, edge-MW, cookie flags, RLS-off, ReDoS, unsafe deser, hardcoded secrets, JWT verification bugs) |
| **C2** | **nuclei** | `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` or binary release | Dynamic HTTP misconfig probes (headers, CORS, CSRF, source maps, clickjacking, SSRF templates, error leakage, DMARC/TLS) |
| **C3** | **Project test runner** | already present in target (pytest+httpx / vitest+supertest) | Adversarial proof execution — all Stage-4/5 `adversarial-test` records run through the project's own runner |
| **C4** | **Native ecosystem audit + gitleaks** | `npm audit` / `pip-audit` / `osv-scanner`; `gitleaks detect` | Dependency CVEs (DEP-001), lockfile checks (DEP-002), secret scanning (SEC-LEAK-001 fallback) |

**Detection logic (runner startup, pseudocode):**

```python
CORE_TOOLS = {
    "semgrep":  ["semgrep", "--version"],
    "nuclei":   ["nuclei", "-version"],
    "gitleaks": ["gitleaks", "version"],
    # test runner detected from project type (see §5 asset detection)
}

def detect_tools() -> dict[str, bool | str]:
    status = {}
    for name, probe in CORE_TOOLS.items():
        try:
            r = subprocess.run(probe, capture_output=True, timeout=5)
            status[name] = r.returncode == 0
        except FileNotFoundError:
            status[name] = False
    # Ecosystem audit: detect from lockfile presence
    if Path("package.json").exists():
        status["npm_audit"] = shutil.which("npm") is not None
    if Path("requirements.txt").exists() or Path("pyproject.toml").exists():
        status["pip_audit"] = (shutil.which("pip-audit") or shutil.which("osv-scanner")) is not None
    return status

def missing_core(tool_status: dict) -> list[str]:
    """Returns list of core-slot tools that are absent with install hint."""
    missing = []
    for slot, name in [("C1","semgrep"),("C2","nuclei"),("C4","gitleaks")]:
        if not tool_status.get(name):
            missing.append(f"{slot} {name}: pip install semgrep  # or: go install nuclei / brew install gitleaks")
    return missing
# Missing core tools do NOT abort the run — each check's strategy[] ladder handles them.
# The runner prints a warning box at startup and routes to the next rung.
```

---

## 2. OPTIONAL ADAPTERS — used-if-present, never required

The runner probes for each before its first use. Detection is a single `which`/`--version`
call cached at startup. If absent → next `strategy[]` rung.

| Adapter | Probe command | Upgrades which checks |
|---|---|---|
| `trufflehog` | `trufflehog --version` | SEC-LEAK-001 (verified secrets, history scan) |
| `osv-scanner` | `osv-scanner --version` | DEP-001 (multi-ecosystem, SBOM-aware) |
| `trivy` | `trivy --version` | DEP-001 (alt SCA), IAC-001 (config scan) |
| `jwt_tool` | `python -m jwt_tool --help` | JWT-001, JWT-002 (confusion/claim matrix) |
| `Playwright` | `playwright --version` | AUTH-STORAGE-001, COOKIE-FLAGS-001 (live browser) |
| `k6` | `k6 version` | RACE-001, RATE-001 (capped concurrency) |
| `interactsh-client` | `interactsh-client -version` | SSRF-001 (OOB callback detection) |
| `stripe` CLI | `stripe --version` | BILLING-WEBHOOK-001 (webhook fixture replay) |
| `sslyze` | `sslyze --version` | CERT-001 (deep TLS/cipher analysis) |
| `checkdmarc` | `checkdmarc --version` | DMARC-001 (SPF/DKIM/DMARC validation) |
| `dnsx` | `dnsx -version` | DNS-001 (CNAME resolution, takeover) |
| `checkov` | `checkov --version` | IAC-001 (opt-in IaC scan) |
| `mitmproxy` | `mitmproxy --version` | WEBHOOK-001, IDEM-001 (replay/mutation) |

**Adapters explicitly NOT in core (Voice 3 binding verdict):**

| Tool | Rejected reason |
|---|---|
| **OWASP ZAP** | Heavy Java process, slow startup, requires project configuration; not compatible with <3s clean-floor promise |
| **Burp Suite** | Licensed, GUI-first; cannot be scripted without Burp REST API pro license |
| **sqlmap** | Aggressive by default, unsafe against staging data, can cause destructive mutations; its coverage is subsumed by C3 adversarial templates for INJ-001 |
| **garak** | Python LLM vuln scanner; requires model API access; cost_generating; optional adapter invoked only on explicit LLM stage opt-in |
| **Wiz / Snyk / Lacework** | Commercial CNAPP — enterprise tier, not a Vercel/Supabase/Stripe founder's toolchain |
| **CodeQL** | Heavy, GitHub Actions-native; good optional CI tool but not runnable locally without setup; semgrep covers the same rules for this registry's purposes |
| **NoSQLMap / tplmap / dalfox** | Specialist single-injection tools; coverage subsumed by C3 adversarial templates (NOSQLI-001, SSTI-001, INJ-001) |

---

## 3. THE `strategy[]` DEGRADATION LADDER

### Schema definition

Every tool-backed check in `registry.yaml` carries a `strategy` array under `tools:`.
The runner walks it top-down and uses the **first rung whose tool is present**. The last
rung is always `{tool: manual, emit: NEEDS-PROOF}` — never a silent skip.

```yaml
# registry.yaml record (partial — full schema in engine/README.md)
- id: SEC-LEAK-001
  # ... other fields ...
  tools:
    strategy:
      - tool: trufflehog
        cmd: "trufflehog git file://. --only-verified --json"
        evidence: json_stdout
        absent_status: skip_to_next
      - tool: gitleaks
        cmd: "gitleaks detect --source . --redact --exit-code 1"
        evidence: exit_code_and_stdout
        absent_status: skip_to_next
      - tool: ripgrep
        cmd: "rg -i --no-heading '(secret|token|api[_-]?key|password)\\s*[:=]\\s*[\"\\x27][^\"\\x27]{8,}'"
        evidence: stdout_lines
        absent_status: skip_to_next
      - tool: manual
        emit: NEEDS-PROOF
        hint: "Run: gitleaks detect --source . OR trufflehog git file://."
```

**Runner logic (pseudocode):**

```python
def execute_strategy(check: dict, tool_status: dict, assets: dict) -> CheckResult:
    for rung in check["tools"]["strategy"]:
        name = rung["tool"]
        if name == "manual":
            return CheckResult(status=NEEDS_PROOF, hint=rung.get("hint",""))
        if not tool_status.get(name, False):
            continue  # tool absent → next rung
        # Tool present — run it
        cmd = interpolate(rung["cmd"], assets)  # fills {target}, {token_A}, etc.
        result = run_command(cmd, timeout=rung.get("timeout_sec", 60))
        evidence = collect_evidence(result, rung["evidence"])
        return interpret_result(result, check, evidence)
    # Should never reach here — manual rung always terminates
    return CheckResult(status=NEEDS_PROOF)
```

### Domain-by-domain strategy ladders

#### Secrets (SEC-LEAK-001, ENV-001, ENV-002, PATTERN-003, FLOOR-A09)

```yaml
# SEC-LEAK-001 — No secret in source or git history
strategy:
  - tool: trufflehog
    cmd: "trufflehog git file://. --only-verified --json"
    evidence: json_stdout
  - tool: gitleaks
    cmd: "gitleaks detect --source . --redact --exit-code 1"
    evidence: exit_code_and_stdout
  - tool: ripgrep
    cmd: "rg -i --no-heading '(SECRET|TOKEN|API[_-]?KEY|PASSWORD)\\s*[:=]\\s*[\"\\x27][^\"\\x27]{8,}'"
    evidence: stdout_lines
  - tool: manual
    emit: NEEDS-PROOF
    hint: "Install gitleaks (brew install gitleaks) and run: gitleaks detect --source ."

# ENV-001 — .gitignore covers .env* before first commit
strategy:
  - tool: semgrep   # file_present auto_probe handles this; strategy is fallback for contents check
    cmd: "semgrep --config rules/env-gitignore.yaml ."
    evidence: sarif
  - tool: ripgrep
    cmd: "rg -l '\\.env' .gitignore .dockerignore"
    evidence: stdout_lines
  - tool: manual
    emit: NEEDS-PROOF

# PATTERN-003 — No hardcoded fallback/default JWT secret
strategy:
  - tool: semgrep
    cmd: "semgrep --config rules/no-default-secret.yaml ."
    evidence: sarif
  - tool: ripgrep
    cmd: "rg -n '(secret|signing_key|jwt_secret).*[\"\\x27](change.?me|your.?secret|development|example|default|secret123|supersecret)'"
    evidence: stdout_lines
  - tool: manual
    emit: NEEDS-PROOF
    hint: "Grep for hardcoded JWT/session secrets; confirm they come from env vars only"

# FLOOR-A09 — Security events logged, no secrets/PII in logs
strategy:
  - tool: semgrep
    cmd: "semgrep --config rules/no-secrets-in-logs.yaml ."
    evidence: sarif
  - tool: ripgrep
    cmd: "rg -n '(logger|console\\.log|print).*\\b(password|token|secret|api_key)'"
    evidence: stdout_lines
  - tool: manual
    emit: NEEDS-PROOF
    hint: "Plant a fake token in a request and assert it does not appear in log output"
```

#### Dependencies / supply chain (DEP-001, DEP-002, DEP-003, CISEC-001)

```yaml
# DEP-001 — No high/critical dependency advisories (runtime-weighted)
strategy:
  - tool: osv-scanner
    cmd: "osv-scanner --format json ."
    evidence: json_stdout
  - tool: trivy
    cmd: "trivy fs --format json --exit-code 1 --severity HIGH,CRITICAL ."
    evidence: json_stdout
  - tool: npm_audit        # ecosystem-native: detected from lockfile
    cmd: "npm audit --json --audit-level=high"
    evidence: json_stdout
  - tool: pip_audit
    cmd: "pip-audit --format json"
    evidence: json_stdout
  - tool: manual
    emit: NEEDS-PROOF
    hint: "Run: npm audit / pip-audit / osv-scanner"

# DEP-002 — Lockfiles committed and version-pinned
strategy:
  - tool: semgrep
    cmd: "semgrep --config rules/lockfile-present.yaml ."
    evidence: sarif
  - tool: ripgrep
    cmd: "rg --files -g 'package-lock.json' -g 'yarn.lock' -g 'Pipfile.lock' -g 'uv.lock' -g 'poetry.lock'"
    evidence: stdout_lines
  - tool: manual
    emit: NEEDS-PROOF

# DEP-003 — CI actions pinned to commit SHA
strategy:
  - tool: semgrep
    cmd: "semgrep --config rules/pinned-actions.yaml .github/"
    evidence: sarif
  - tool: ripgrep
    cmd: "rg -n 'uses:\\s+[^@]+@(?!\\b[0-9a-f]{40}\\b)' .github/workflows/"
    evidence: stdout_lines     # non-SHA pins flagged as FAIL
  - tool: manual
    emit: NEEDS-PROOF
```

#### Dynamic headers / misconfig (HDR-001, HDR-002, CLICKJACK-001, SOURCEMAP-001, ERRORLEAK-001)

```yaml
# HDR-001 — Security headers present
strategy:
  - tool: nuclei
    cmd: "nuclei -t http/misconfiguration/http-missing-security-headers.yaml -u {target_url} -json"
    evidence: json_stdout
  - tool: manual
    emit: NEEDS-PROOF
    hint: "curl -I {target_url} and assert: Strict-Transport-Security, X-Content-Type-Options, Content-Security-Policy"

# HDR-002 — CORS does not reflect arbitrary Origin with credentials
strategy:
  - tool: nuclei
    cmd: "nuclei -t http/misconfiguration/cors-misconfiguration.yaml -u {target_url} -json"
    evidence: json_stdout
  - tool: manual
    emit: NEEDS-PROOF
    hint: "Send: Origin: https://evil.example.com with credentials; assert header not reflected"

# SOURCEMAP-001 — Production source maps not served
strategy:
  - tool: nuclei
    cmd: "nuclei -t http/misconfiguration/exposed-sourcemaps.yaml -u {target_url} -json"
    evidence: json_stdout
  - tool: ripgrep
    cmd: "rg --files -g '*.map' dist/ .next/static/ build/"
    evidence: stdout_lines      # presence of .map files in build artifacts = FAIL signal
  - tool: manual
    emit: NEEDS-PROOF

# ERRORLEAK-001 — Error responses sanitized
strategy:
  - tool: nuclei
    cmd: "nuclei -t http/misconfiguration/error-handling.yaml -u {target_url} -json"
    evidence: json_stdout
  - tool: manual
    emit: NEEDS-PROOF
    hint: "Send malformed/404 requests and assert no stack traces, SQL errors, or internal paths in response"
```

#### JWT (JWT-001, JWT-002, PATTERN-004)

```yaml
# JWT-001 — JWT decode rejects none/confusion/missing-exp/expired/tampered/aud
strategy:
  - tool: jwt_tool
    cmd: "python -m jwt_tool {sample_jwt} -X a -t {target_url}/api/protected -rh 'Authorization: Bearer {tampered}'"
    evidence: stdout_lines
  - tool: project_test_runner   # C3: the adversarial template in templates/<stack>/test_jwt_hardening.*
    cmd: "{test_runner} {template_path}/test_jwt_hardening.{ext}"
    evidence: test_result
  - tool: manual
    emit: NEEDS-PROOF
    hint: "Run templates/python-fastapi/test_jwt_hardening.py or templates/typescript-node/jwt_hardening.test.ts"

# JWT-002 — Token-purpose confusion rejected
strategy:
  - tool: project_test_runner
    cmd: "{test_runner} {template_path}/test_token_purpose.{ext}"
    evidence: test_result
  - tool: manual
    emit: NEEDS-PROOF
    hint: "Replay every non-access token type (reset/2fa/email-verify) on a protected route; expect 401"

# PATTERN-004 — No alg-family-only or unpinned JWT verification
strategy:
  - tool: semgrep
    cmd: "semgrep --config rules/jwt-algorithm-pinning.yaml ."
    evidence: sarif
  - tool: ripgrep
    cmd: "rg -n '(algorithms=\\[|alg.*=.*(HS|RS|ES)(?!256|384|512))'"
    evidence: stdout_lines
  - tool: manual
    emit: NEEDS-PROOF
```

#### SSRF (SSRF-001)

```yaml
# SSRF-001 — Server fetch validates resolved IP and re-validates after redirects
strategy:
  - tool: interactsh-client
    # Sends an interactsh OOB URL through the fetch endpoint; detects DNS/HTTP callbacks
    cmd: "interactsh-client -server oast.pro -json &; {test_runner} {template_path}/test_ssrf.{ext} --oob-domain {interactsh_host}"
    evidence: interactsh_json_and_test_result
  - tool: project_test_runner
    # Falls back to controlled local server (127.0.0.1:TESTPORT) to assert blocked
    cmd: "{test_runner} {template_path}/test_ssrf.{ext} --local-only"
    evidence: test_result
  - tool: manual
    emit: NEEDS-PROOF
    hint: "Send fetch target pointing to 169.254.169.254 and localhost; assert both blocked. Check redirect re-validation."
```

#### Billing / webhooks (BILLING-WEBHOOK-001, WEBHOOK-001, IDEM-001)

```yaml
# BILLING-WEBHOOK-001 — Stripe sig-verify + out-of-order/duplicate events
strategy:
  - tool: stripe       # Stripe CLI present: use native test fixture + trigger
    cmd: "stripe fixtures bedrock-stripe-fixture.json && stripe trigger payment_intent.succeeded --add payment_intent:metadata.bedrock_test=1"
    evidence: stripe_stdout
  - tool: project_test_runner
    cmd: "{test_runner} {template_path}/test_billing_webhook.{ext}"
    evidence: test_result
  - tool: manual
    emit: NEEDS-PROOF
    hint: "Replay a webhook event with: (1) bad signature, (2) duplicate ID, (3) out-of-order cancel→charge"

# WEBHOOK-001 — HMAC over raw body, replay window, idempotent
strategy:
  - tool: mitmproxy
    cmd: "mitmdump --mode reverse:{target_url} -s scripts/bedrock_webhook_replay.py"
    evidence: mitmproxy_stdout
  - tool: project_test_runner
    cmd: "{test_runner} {template_path}/test_webhook.{ext}"
    evidence: test_result
  - tool: manual
    emit: NEEDS-PROOF
    hint: "Send webhook with: (1) stripped sig header, (2) replayed timestamp >5min old, (3) same idempotency key twice"
```

#### DNS / TLS (DMARC-001, CERT-001, DNS-001)

```yaml
# DMARC-001 — SPF/DKIM/DMARC configured
strategy:
  - tool: checkdmarc
    cmd: "checkdmarc {domain} --output-format json"
    evidence: json_stdout
  - tool: manual
    # Stdlib fallback: dns.resolver (Python stdlib since 3.x) — zero deps
    cmd: "python -c \"import dns.resolver; print(dns.resolver.resolve('_dmarc.{domain}','TXT').response)\""
    evidence: stdout_lines
  - tool: manual
    emit: NEEDS-PROOF
    hint: "Check: dig TXT _dmarc.{domain}; dig TXT {domain} (SPF); verify DMARC policy is quarantine or reject"

# CERT-001 — Valid cert, no weak TLS versions/ciphers, HSTS set
strategy:
  - tool: sslyze
    cmd: "sslyze --json_out={out_dir}/sslyze.json {domain}"
    evidence: json_file
  - tool: nuclei
    cmd: "nuclei -t ssl/ -u {target_url} -json"
    evidence: json_stdout
  - tool: manual
    # Python stdlib TLS handshake probe (no external tools)
    cmd: "python -c \"import ssl,socket; ctx=ssl.create_default_context(); ctx.check_hostname=True; s=ctx.wrap_socket(socket.create_connection(('{domain}',443)),server_hostname='{domain}'); print(s.version(),s.cipher())\""
    evidence: stdout_lines
  - tool: manual
    emit: NEEDS-PROOF
    hint: "Verify cert chain, TLS >=1.2 (1.3 preferred), HSTS header present"

# DNS-001 — No dangling CNAMEs / subdomain takeover risk
strategy:
  - tool: dnsx
    cmd: "dnsx -l {subdomains_list} -cname -json"
    evidence: json_stdout
  - tool: manual
    # Python stdlib fallback: resolve every CNAME and detect NXDOMAIN on the target
    cmd: "python bedrock_dns_check.py {domain}"
    evidence: stdout_lines
  - tool: manual
    emit: NEEDS-PROOF
    hint: "For each subdomain CNAME, verify the target resolves. NXDOMAIN on a CNAME target = takeover risk"
```

---

## 4. THE `safety{}` FLAG SCHEMA

### Schema definition

```yaml
# Appended to every check record in registry.yaml
safety:
  destructive:          false   # true = mutates/deletes real data (RACE, TENANT-DEL)
  cost_generating:      false   # true = bills (LLM tokens, SMS, paid webhook triggers)
  needs_seed_data:      false   # true = requires tenant A/B fixtures seeded first
  readonly:             true    # true = only reads; never mutates state
  safe_in_prod:         true    # true = permitted against a production target
  external_side_effect: false   # true = sends real email/SMS/payment/webhook to external systems
```

**Enforcement rule:** `sweep.py --env=<env>` refuses to execute a check if its `safety`
profile is incompatible with the environment. See §5 for the matrix.

### Per-check `safety{}` values (all 76 existing + IN additions)

#### Stage 0 — SCOPE & SAFETY

| id | destructive | cost_generating | needs_seed_data | readonly | safe_in_prod | external_side_effect |
|---|---|---|---|---|---|---|
| INV-007 | false | false | false | true | true | false |
| DEPLOY-GATE-001 | false | false | false | true | true | false |
| SCOPE-001 *(new)* | false | false | false | true | true | false |
| DATA-SAFETY-001 *(new)* | false | false | false | true | true | false |

#### Stage 1 — FRAME (inventory, asset generation)

| id | destructive | cost_generating | needs_seed_data | readonly | safe_in_prod | external_side_effect |
|---|---|---|---|---|---|---|
| INV-001 | false | false | false | true | true | false |
| INV-002 | false | false | false | true | true | false |
| INV-003 | false | false | false | true | true | false |
| INV-004 | false | false | false | true | true | false |
| INV-005 | false | false | false | true | true | false |
| INV-006 | false | false | false | true | true | false |
| INV-008 | false | false | false | true | true | false |
| APIINV-001 | false | false | false | true | true | false |

#### Stage 2 — STATIC

| id | destructive | cost_generating | needs_seed_data | readonly | safe_in_prod | external_side_effect |
|---|---|---|---|---|---|---|
| SEC-LEAK-001 | false | false | false | true | true | false |
| ENV-001 | false | false | false | true | true | false |
| ENV-002 | false | false | false | true | true | false |
| PATTERN-001 | false | false | false | true | true | false |
| PATTERN-002 | false | false | false | true | true | false |
| PATTERN-003 | false | false | false | true | true | false |
| PATTERN-004 | false | false | false | true | true | false |
| REDOS-001 | false | false | false | true | true | false |
| DEP-001 | false | false | false | true | true | false |
| DEP-002 | false | false | false | true | true | false |
| DEP-003 | false | false | false | true | true | false |
| FLOOR-A02 | false | false | false | true | true | false |
| FLOOR-A03 | false | false | false | true | true | false |
| FLOOR-A05 | false | false | false | true | true | false |
| FLOOR-A08 | false | false | false | true | true | false |
| FLOOR-A09 | false | false | false | true | true | false |
| CLIENT-ENV-001 | false | false | false | true | true | false |
| SOURCEMAP-001 | false | false | false | true | true | false |
| COOKIE-FLAGS-001 | false | false | false | true | true | false |
| CLICKJACK-001 | false | false | false | true | true | false |
| HDR-001 | false | false | false | true | true | false |
| HDR-002 | false | false | false | true | true | false |
| CISEC-001 | false | false | false | true | true | false |
| TEST-ISO-001 | false | false | false | true | true | false |
| DOC-FRESH-001 | false | false | false | true | true | false |
| SBA-ANON-001 *(new)* | false | false | false | true | true | false |
| NEXT-RSC-001 *(new)* | false | false | false | true | true | false |
| IAC-001 *(new, opt-in)* | false | false | false | true | true | false |

#### Stage 3 — DYNAMIC-PASSIVE (preview / prod-readonly)

| id | destructive | cost_generating | needs_seed_data | readonly | safe_in_prod | external_side_effect |
|---|---|---|---|---|---|---|
| HDR-001 (live) | false | false | false | true | true | false |
| HDR-002 (live) | false | false | false | true | true | false |
| CLICKJACK-001 (live) | false | false | false | true | true | false |
| COOKIE-FLAGS-001 (live) | false | false | false | true | true | false |
| SOURCEMAP-001 (live) | false | false | false | true | true | false |
| ERRORLEAK-001 | false | false | false | true | **false** | false |
| AUTHN-REQUIRED-001 | false | false | false | true | **false** | false |
| SIZE-001 | false | false | false | true | **false** | false |
| PAGINATION-001 | false | false | false | true | **false** | false |
| DMARC-001 *(new)* | false | false | false | true | true | false |
| CERT-001 *(new)* | false | false | false | true | true | false |
| DNS-001 *(new)* | false | false | false | true | true | false |

> Note: `ERRORLEAK-001`, `AUTHN-REQUIRED-001`, `SIZE-001`, `PAGINATION-001` are passive HTTP probes
> that send abnormal requests; they are safe on preview but **not safe on prod** because they may
> trigger rate limits, alerting, or cause real-user-visible 400/413 errors.

#### Stage 4 — DYNAMIC-ADVERSARIAL (seeded staging only)

| id | destructive | cost_generating | needs_seed_data | readonly | safe_in_prod | external_side_effect |
|---|---|---|---|---|---|---|
| AUTHZ-SERVER-001 | false | false | **true** | false | **false** | false |
| BOLA-001 | false | false | **true** | false | **false** | false |
| BFLA-001 | false | false | **true** | false | **false** | false |
| MASS-001 | false | false | **true** | false | **false** | false |
| EXCESSDATA-001 | false | false | **true** | false | **false** | false |
| SUPABASE-RLS-001 | false | false | **true** | false | **false** | false |
| TENANT-DEL-001 | **true** | false | **true** | false | **false** | false |
| AUDIT-001 | false | false | **true** | false | **false** | false |
| PATHTRAV-001 | false | false | false | false | **false** | false |
| REDIRECT-001 | false | false | false | false | **false** | false |
| WEBSOCKET-001 | false | false | **true** | false | **false** | false |
| JWT-001 | false | false | **true** | false | **false** | false |
| JWT-002 | false | false | **true** | false | **false** | false |
| TOKEN-ROTATE-001 | false | false | **true** | false | **false** | false |
| OAUTH-001 | false | false | **true** | false | **false** | false |
| PWPOLICY-001 | false | false | false | false | **false** | false |
| LOCK-001 | false | false | false | false | **false** | false |
| ACCT-VERIFY-001 | false | false | false | true | **false** | false |
| AUTH-STORAGE-001 | false | false | **true** | false | **false** | false |
| TIMING-001 | false | false | **true** | false | **false** | false |
| INJ-001 | false | false | **true** | false | **false** | false |
| XXE-001 | false | false | false | false | **false** | false |
| SSTI-001 | false | false | false | false | **false** | false |
| NOSQLI-001 | false | false | false | false | **false** | false |
| HOSTHDR-001 | false | false | false | false | **false** | false |
| SSRF-001 | false | false | false | false | **false** | false |
| WEBHOOK-001 | false | false | **true** | false | **false** | **true** |
| IDEM-001 | false | false | **true** | false | **false** | false |
| RACE-001 | **true** | false | **true** | false | **false** | false |
| RATE-001 | false | false | **true** | false | **false** | false |
| EDGE-MW-001 *(new)* | false | false | false | false | **false** | false |
| BILLING-WEBHOOK-001 *(new)* | false | **true** | **true** | false | **false** | **true** |
| ENTITLEMENT-001 *(new)* | false | false | **true** | false | **false** | false |
| CACHE-TENANT-001 *(new)* | false | false | **true** | false | **false** | false |
| SEARCH-TENANT-001 *(new)* | false | false | **true** | false | **false** | false |
| ANALYTICS-PII-001 *(new)* | false | false | false | false | **false** | false |

#### Stage 5 — LLM/AI

| id | destructive | cost_generating | needs_seed_data | readonly | safe_in_prod | external_side_effect |
|---|---|---|---|---|---|---|
| LLM-INJ-001 | false | **true** | **true** | false | **false** | false |
| LLM-OUT-001 | false | **true** | **true** | false | **false** | false |
| LLM-FAILOPEN-001 | false | false | false | false | **false** | false |
| LLM-BLIND-001 *(new)* | false | **true** | false | false | **false** | false |
| RAG-TENANT-001 *(new)* | false | **true** | **true** | false | **false** | false |

#### Stage 6 — DECISION / TRIAGE / VERDICT

| id | destructive | cost_generating | needs_seed_data | readonly | safe_in_prod | external_side_effect |
|---|---|---|---|---|---|---|
| DEC-001 | false | false | false | true | true | false |
| DEC-002 | false | false | false | true | true | false |
| CSRF-001 | false | false | false | true | true | false |
| TRIAGE-001 | false | false | false | true | true | false |
| TEST-ISO-001 (verdict) | false | false | false | true | true | false |
| DOC-FRESH-001 (final) | false | false | false | true | true | false |
| DEPLOY-GATE-001 (final) | false | false | false | true | true | false |

---

## 5. THE `--env` ENFORCEMENT MATRIX

### Flag → allowed `safety` profile

```python
ENV_POLICY = {
    "pre-commit": {
        "allow_destructive":          False,
        "allow_cost_generating":      False,
        "allow_needs_seed_data":      False,
        "require_readonly":           True,
        "require_safe_in_prod":       True,
        "allow_external_side_effect": False,
    },
    "ci": {
        "allow_destructive":          False,
        "allow_cost_generating":      False,
        "allow_needs_seed_data":      False,
        "require_readonly":           True,
        "require_safe_in_prod":       True,   # CI runs against build artifacts, not live app
        "allow_external_side_effect": False,
    },
    "preview": {
        "allow_destructive":          False,
        "allow_cost_generating":      False,
        "allow_needs_seed_data":      False,
        "require_readonly":           False,  # passive live HTTP probes allowed
        "require_safe_in_prod":       False,  # preview is ephemeral, not prod
        "allow_external_side_effect": False,
    },
    "staging": {
        "allow_destructive":          True,
        "allow_cost_generating":      True,   # but LLM stage must be opted-in explicitly
        "allow_needs_seed_data":      True,
        "require_readonly":           False,
        "require_safe_in_prod":       False,
        "allow_external_side_effect": True,   # webhook/billing providers in test mode
    },
    "prod": {
        "allow_destructive":          False,
        "allow_cost_generating":      False,
        "allow_needs_seed_data":      False,
        "require_readonly":           True,
        "require_safe_in_prod":       True,
        "allow_external_side_effect": False,
    },
}

def env_allows_check(check: dict, env: str) -> bool:
    policy = ENV_POLICY[env]
    s = check["safety"]
    if s["destructive"] and not policy["allow_destructive"]:
        return False
    if s["cost_generating"] and not policy["allow_cost_generating"]:
        return False
    if s["needs_seed_data"] and not policy["allow_needs_seed_data"]:
        return False
    if policy["require_readonly"] and not s["readonly"]:
        return False
    if policy["require_safe_in_prod"] and not s["safe_in_prod"]:
        return False
    if s["external_side_effect"] and not policy["allow_external_side_effect"]:
        return False
    return True

# In sweep.py main loop:
if not env_allows_check(check, args.env):
    ledger.add(check["id"], status=BLOCKED, reason=f"safety profile incompatible with --env={args.env}")
    continue
```

**Default env:** `preview` — safe for any developer running the tool without thinking.
An operator must explicitly pass `--env=staging` to unlock adversarial checks, and
`--env=prod` to restrict to prod-safe-only. No adversarial checks fire by accident.

---

## 6. THE 5-ENVIRONMENT → CHECK-ID MAPPING (final)

### pre-commit

Runs locally in <30 seconds. No network, no live app.

```
SEC-LEAK-001   ENV-001   ENV-002   PATTERN-003   PATTERN-004
REDOS-001      FLOOR-A03 FLOOR-A08 CLIENT-ENV-001
SBA-ANON-001   NEXT-RSC-001
```

### ci (pull-request + build artifact)

Extends pre-commit. Runs against source + built artifacts. No running app required.

```
# All pre-commit checks, plus:
DEP-001        DEP-002        DEP-003        CISEC-001
PATTERN-001    PATTERN-002    FLOOR-A05      FLOOR-A09
SOURCEMAP-001  COOKIE-FLAGS-001 (static)     TEST-ISO-001
DOC-FRESH-001  FLOOR-A02      IAC-001 (if *.tf / vercel.json / compose present)
HDR-001 (static posture check only, not live)
HDR-002 (static CORS config, not live)
```

### preview (ephemeral URL — passive dynamic)

Requires a running app with a reachable URL. No seeded data needed.

```
HDR-001        HDR-002        CLICKJACK-001
COOKIE-FLAGS-001 (live)       SOURCEMAP-001 (live)
ERRORLEAK-001  AUTHN-REQUIRED-001            SIZE-001
PAGINATION-001 DMARC-001      CERT-001       DNS-001
EDGE-MW-001 (passive URL-casing probe — no fixtures required for passive variant)
```

### staging (seeded adversarial — the full suite)

Requires: seeded tenant A/B, provider test modes (Stripe test key, mocked LLM gateway
for Stage 5), rollback confirmed, `--env=staging` flag.

```
# All of Stage 4 (adversarial):
AUTHZ-SERVER-001  BOLA-001      BFLA-001      MASS-001
EXCESSDATA-001    SUPABASE-RLS-001  TENANT-DEL-001  AUDIT-001
PATHTRAV-001      REDIRECT-001  WEBSOCKET-001
JWT-001           JWT-002       TOKEN-ROTATE-001  OAUTH-001
PWPOLICY-001      LOCK-001      ACCT-VERIFY-001   AUTH-STORAGE-001
TIMING-001        INJ-001       XXE-001        SSTI-001
NOSQLI-001        HOSTHDR-001   SSRF-001
WEBHOOK-001       IDEM-001      RACE-001       RATE-001
EDGE-MW-001 (full adversarial)  BILLING-WEBHOOK-001  ENTITLEMENT-001
CACHE-TENANT-001  SEARCH-TENANT-001  ANALYTICS-PII-001

# All of Stage 5 (LLM/AI — requires explicit --stages=llm opt-in due to cost_generating):
LLM-INJ-001   LLM-OUT-001   LLM-FAILOPEN-001  LLM-BLIND-001  RAG-TENANT-001
```

### prod (read-only passive — never adversarial)

Only checks where `readonly:true AND safe_in_prod:true`.

```
HDR-001        HDR-002        CLICKJACK-001
SOURCEMAP-001  COOKIE-FLAGS-001 (live, read-only check)
FLOOR-A02      CERT-001       DMARC-001      DNS-001
APIINV-001 (passive — from gateway/logs/spec, not active probe)
AUDIT-001 (config-read variant — read log sink config, not inject events)
DEC-001        DEC-002        DEPLOY-GATE-001
```

---

## 7. THE FULL `tools:` / `strategy:` / `safety:` YAML SCHEMA

This is the complete record schema addition for `engine/registry.yaml`. Existing 76
records without these keys fall back to defaults (no-dep, all-env, readonly).

```yaml
# Full extended check record — every field annotated
- id: BOLA-001
  title: "Object authz — cross-identity access returns indistinguishable 404"
  domain: access-control
  phase: adversarial
  severity: critical
  method: adversarial-test
  oracle: [OWASP API1:2023, CWE-639]
  applicability:
    question: "Does the app have multi-tenant or per-user owned objects?"
    auto_probe:
      type: grep_present
      patterns: ['tenant_id', 'user_id', 'owner_id', 'org_id']
      langs: [py, ts, js, sql]
  proof:
    description: "Tenant B token requests Tenant A object; response must be indistinguishable from non-existent"
    templates:
      python-fastapi: templates/python-fastapi/test_bola.py
      typescript-node: templates/typescript-node/bola.test.ts
      supabase-postgres: templates/supabase-postgres/bola_rls.sql
  pass_criteria: "Response to cross-tenant request === response for non-existent object (status, body shape, error text)"
  fail_action: "Object authz is missing or leaks existence via status/body difference — fix server-side ownership check"
  ref: references/hardening-playbook.md#1

  # --- NEW FIELDS (S2 spec) ---

  # DAG (owned by S1, referenced here for completeness)
  requires:     [INV-001, INV-005]
  provides:     []
  blocks_if_fail: true
  environments: [staging]

  # Tool adapter (S2)
  tools:
    strategy:
      - tool: project_test_runner
        cmd: "{test_runner} {template_path}/test_bola.{ext}"
        evidence: test_result
        timeout_sec: 60
        absent_status: skip_to_next
      - tool: manual
        emit: NEEDS-PROOF
        hint: "Copy templates/python-fastapi/test_bola.py, wire to real routes from assets.json, run pytest"

  # Safety flags (S2)
  safety:
    destructive:          false
    cost_generating:      false
    needs_seed_data:      true
    readonly:             false
    safe_in_prod:         false
    external_side_effect: false
```

### Second example — SEC-LEAK-001 (multi-rung strategy)

```yaml
- id: SEC-LEAK-001
  title: "No secret present in source or git history"
  domain: secrets-logging
  phase: static
  severity: critical
  method: static-scan
  oracle: [CWE-532]
  applicability:
    question: "Always applicable"
    auto_probe:
      type: file_present
      patterns: ["*.py", "*.ts", "*.js", "*.env*"]
  proof:
    description: "Secret scanner returns zero findings across all commits"
    templates: {}
  pass_criteria: "Scanner exits 0 with no verified secrets"
  fail_action: "Revoke and rotate the found credential immediately; remove from history with BFG/filter-repo"
  ref: references/secrets-and-ops.md

  requires:     [INV-004]
  provides:     [assets.secrets_clean_flag]
  blocks_if_fail: true
  environments: [pre-commit, ci, preview, staging, prod]

  tools:
    strategy:
      - tool: trufflehog
        cmd: "trufflehog git file://. --only-verified --json"
        evidence: json_stdout
        timeout_sec: 120
      - tool: gitleaks
        cmd: "gitleaks detect --source . --redact --exit-code 1"
        evidence: exit_code_and_stdout
        timeout_sec: 60
      - tool: ripgrep
        cmd: "rg -i --no-heading '(SECRET|TOKEN|API[_-]?KEY|PASSWORD)\\s*[:=]\\s*[\"\\x27][^\"\\x27]{8,}'"
        evidence: stdout_lines
        timeout_sec: 30
      - tool: manual
        emit: NEEDS-PROOF
        hint: "Install gitleaks (brew install gitleaks) then: gitleaks detect --source ."

  safety:
    destructive:          false
    cost_generating:      false
    needs_seed_data:      false
    readonly:             true
    safe_in_prod:         true
    external_side_effect: false
```

---

## 8. "EXPLICITLY NOT IN CORE" EXCLUSION LIST

| Tool | Exclusion class | Rationale |
|---|---|---|
| **OWASP ZAP** | Required-core exclusion | JVM startup overhead (3-8s alone), project-specific configuration required, active scan mode is destructive by default. Nuclei covers the same HTTP misconfig checks in milliseconds, requires zero config, and degrades gracefully. |
| **Burp Suite** | Required-core exclusion | GUI-first, proprietary (Pro license for scripted API), not automatable without `burpsuite_pro` REST API. Cannot satisfy the clean-floor promise. Subsumed by nuclei + project test runner. |
| **sqlmap** | Required-core exclusion | Aggressive-by-default mode causes real DB mutations, timeouts, and connection exhaustion. Not safe against staging without explicit `--level` tuning. INJ-001 is proven by the adversarial template (C3), not a fuzzer. |
| **garak** | Required-core exclusion (optional adapter) | Requires model API access at test time → `cost_generating:true`; LLM stage is already the only cost-generating stage. Garak adds config overhead for little marginal gain over the C3 adversarial templates for LLM-INJ-001/LLM-OUT-001. May be invoked as an optional adapter when explicitly opted in. |
| **Wiz / Lacework / Orca** | Permanent rejection | Commercial CNAPP — licensed, cloud-agent-deployed, not CLI-first. K8s/multi-cloud focus is irrelevant to the Vercel/Supabase/Stripe target stack. |
| **Snyk** | Permanent rejection | Proprietary SaaS, requires token, network call per scan. osv-scanner/pip-audit/npm audit cover the same DEP-001/DEP-002 surface for free and offline. |
| **K8s toolchain (kube-score, kubescape, polaris)** | Permanent rejection | Target stack has no Kubernetes tier. Voice-3 verdict: CONTAINER-001/K8S-001 are REJECT for this product. |
| **SBOM/SIGN/PROVENANCE (Syft, Cosign, SLSA)** | Permanent rejection | Supply-chain provenance theater for a 2-person team. DEP-001/002/003 cover the real risk. |
| **Jira/Linear/GitHub issue sync** | Permanent rejection | Audit-bureaucracy. The ledger RED is the SLA (Gemini). Not a scanning tool — a lifecycle management concern out of scope. |
| **CodeQL** | Optional adapter only | Heavy, GitHub Actions–native, slow local setup. Semgrep (C1) covers the same SAST rules from the registry. CodeQL is a valid optional rung if present but never a blocking dependency. |
| **NoSQLMap, tplmap, dalfox, commix** | Optional adapters only | Single-vulnerability-class fuzzers. Subsumed by C3 adversarial templates. May be probed as optional upgrades for NOSQLI-001, SSTI-001, INJ-001 strategy ladders respectively when present. |

---

## 9. TOOL DETECTION STARTUP SEQUENCE (runner implementation)

```python
# engine/tool_registry.py

OPTIONAL_ADAPTERS = {
    "trufflehog":       ["trufflehog", "--version"],
    "osv-scanner":      ["osv-scanner", "--version"],
    "trivy":            ["trivy", "--version"],
    "jwt_tool":         ["python", "-m", "jwt_tool", "--help"],
    "playwright":       ["playwright", "--version"],
    "k6":               ["k6", "version"],
    "interactsh-client":["interactsh-client", "-version"],
    "stripe":           ["stripe", "--version"],
    "sslyze":           ["sslyze", "--version"],
    "checkdmarc":       ["checkdmarc", "--version"],
    "dnsx":             ["dnsx", "-version"],
    "checkov":          ["checkov", "--version"],
    "mitmproxy":        ["mitmproxy", "--version"],
    "ripgrep":          ["rg", "--version"],
    "dnspython":        ["python", "-c", "import dns; print(dns.__version__)"],
    # Ecosystem-native (detected from project structure, not PATH)
    "npm_audit":        None,   # detected from package-lock.json + which(npm)
    "pip_audit":        None,   # detected from requirements.txt + which(pip-audit)
    "project_test_runner": None,  # detected from pytest.ini/pyproject.toml/vitest.config.*
}

def detect_all_tools(project_root: Path) -> dict[str, bool]:
    status = {}
    for name, probe in {**CORE_TOOLS, **OPTIONAL_ADAPTERS}.items():
        if probe is None:
            status[name] = _detect_ecosystem_tool(name, project_root)
        else:
            try:
                r = subprocess.run(probe, capture_output=True, timeout=5)
                status[name] = r.returncode == 0
            except (FileNotFoundError, subprocess.TimeoutExpired):
                status[name] = False
    return status

def _detect_ecosystem_tool(name: str, root: Path) -> bool:
    if name == "npm_audit":
        return (root / "package-lock.json").exists() and shutil.which("npm") is not None
    if name == "pip_audit":
        has_reqs = (root / "requirements.txt").exists() or (root / "pyproject.toml").exists()
        has_tool = shutil.which("pip-audit") or shutil.which("osv-scanner")
        return has_reqs and bool(has_tool)
    if name == "project_test_runner":
        pytest_markers = ["pytest.ini", "pyproject.toml", "setup.cfg", "conftest.py"]
        vitest_markers = ["vitest.config.ts", "vitest.config.js", "vitest.config.mts"]
        return (
            any((root / m).exists() for m in pytest_markers) or
            any((root / m).exists() for m in vitest_markers)
        )
    return False

def startup_report(tool_status: dict) -> str:
    """Printed once at runner start. Shows core slots and detected optionals."""
    lines = ["Tool detection:"]
    for slot, name in [("C1","semgrep"),("C2","nuclei"),("C3","project_test_runner"),("C4","gitleaks")]:
        ok = tool_status.get(name, False)
        lines.append(f"  [{slot}] {name}: {'OK' if ok else 'MISSING — checks will degrade to next rung'}")
    optionals = [n for n,v in tool_status.items() if v and n not in ("semgrep","nuclei","gitleaks","project_test_runner")]
    if optionals:
        lines.append(f"  Optional adapters present: {', '.join(optionals)}")
    return "\n".join(lines)
```

---

## 10. SUMMARY — the contract in one page

**4-tool mandatory core:** semgrep (C1) + nuclei (C2) + project test runner (C3) + native
ecosystem audit + gitleaks (C4). Tool detection runs at startup; missing core slots degrade
per `strategy[]`, never abort.

**Strategy ladder pattern:** every tool-backed check carries `tools.strategy[]` (top = ideal,
bottom = `{tool:manual, emit:NEEDS-PROOF}`). Runner walks top-down, first present tool wins.
The last rung is never skipped silently — it emits `NEEDS-PROOF` + the exact command.

**6 safety flags per check:** `destructive` / `cost_generating` / `needs_seed_data` /
`readonly` / `safe_in_prod` / `external_side_effect`. Each is a boolean. Defaults:
`{destructive:false, cost_generating:false, needs_seed_data:false, readonly:true, safe_in_prod:true, external_side_effect:false}`.

**5-environment enforcement:** `--env=pre-commit|ci|preview|staging|prod` (default: `preview`).
Before running any check the runner asserts its `safety` profile is compatible with the env
policy; incompatible checks get `BLOCKED(env)` in the ledger, never silently skipped.

**Explicitly NOT in core:** ZAP, Burp, sqlmap, garak, Wiz/Snyk/CNAPP, K8s toolchain, SBOM/
provenance chain, Jira/ticket sync. The first four may appear as optional adapters; the rest
are permanent rejections for this product scope.
