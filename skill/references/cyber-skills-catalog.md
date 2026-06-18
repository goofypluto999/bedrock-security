# Cyber Skills Catalogue — the 754-skill corpus, captured by reference

> Source: **[mukul975/Anthropic-Cybersecurity-Skills](https://github.com/mukul975/Anthropic-Cybersecurity-Skills)**
> — 754 skills · 26 domains · 5-framework mapping · **Apache-2.0** · by **Mahipal
> Jangra (@mukul975)**. *Independent community project, not affiliated with Anthropic.*
> Credited here under Apache-2.0; we extract concepts (OWASP/CWE techniques aren't
> copyrightable) and catalogue the rest by reference.

## Why by-reference, not vendored

That corpus and bedrock are **two different disciplines**:
- **bedrock** = *build/harden a secure app* — a gated sweep that PROVES each control
  on YOUR app (BOLA, JWT, rate limits, RLS…). Units are pass/fail **checks**.
- **the corpus** = *operate as a security analyst* — DFIR, malware reverse-engineering,
  threat hunting, IR, red-team. Units are investigation **playbooks** (`analyzing-*`,
  `hunting-*`, `exploiting-*`), not things an app "passes".

Melting 754 DFIR playbooks into the app-sweep registry would dilute the engine, mix
disciplines, and bloat context. So instead: the **app-security-relevant techniques are
promoted into the registry as real checks** (below), and the **full corpus is
catalogued + pullable on demand** when an investigation/pentest/IR task actually arises.
That captures the value of "all of it" without breaking the focused system.

### Pull a skill on demand
```bash
git clone --depth 1 https://github.com/mukul975/Anthropic-Cybersecurity-Skills /tmp/acs
# then read /tmp/acs/skills/<skill-name>/SKILL.md  (+ references/, scripts/)
```
> Many corpus skills are **offensive/dual-use** (exploitation, red-team, cracking).
> Use them only under authorization — pentest engagement, CTF, your own systems, or
> defensive research. Same rule this skill operates under.

## The 26 domains (corpus breakdown)

| Domain | Skills | | Domain | Skills |
|---|--:|---|---|--:|
| Cloud Security | 60 | | Penetration Testing | 23 |
| Threat Hunting | 55 | | Endpoint Security | 17 |
| Threat Intelligence | 50 | | DevSecOps | 17 |
| Web Application Security | 42 | | Phishing Defense | 16 |
| Network Security | 40 | | Cryptography | 14 |
| Malware Analysis | 39 | | Zero Trust Architecture | 13 |
| Digital Forensics | 37 | | Mobile Security | 12 |
| Security Operations | 36 | | Ransomware Defense | 7 |
| Identity & Access Management | 35 | | Compliance & Governance | 5 |
| SOC Operations | 33 | | Deception Technology | 2 |
| Container Security | 30 | | OT/ICS Security | 28 |
| API Security | 28 | | Vulnerability Management | 25 |
| Incident Response | 25 | | Red Teaming | 24 |

## App-security-relevant subset (186 skills) → what we did with each

**Promoted into the bedrock registry as checks** (technique → check id):
- `testing-api-for-broken-object-level-authorization`, `detecting-broken-object-property-level-authorization` → **BOLA-001**
- `exploiting-broken-function-level-authorization` → **BFLA-001**
- `testing-api-for-mass-assignment-vulnerability` → **MASS-001**
- `testing-for-broken-access-control`, `bypassing-authentication-with-forced-browsing` → **AUTHN-REQUIRED-001 / AUTHZ-SERVER-001**
- `exploiting-excessive-data-exposure-in-api` → **EXCESSDATA-001**
- `detecting-shadow-api-endpoints`, `performing-api-inventory-and-discovery` → **APIINV-001**
- `performing-directory-traversal-testing` → **PATHTRAV-001**
- `testing-for-open-redirect-vulnerabilities` → **REDIRECT-001**
- `testing-websocket-api-security`, `exploiting-websocket-vulnerabilities` → **WEBSOCKET-001**
- `exploiting-sql-injection-*`, `performing-second-order-sql-injection`, `testing-for-xss-vulnerabilities` → **INJ-001 / FLOOR-A03**
- `exploiting-template-injection-vulnerabilities` → **SSTI-001**
- `exploiting-nosql-injection-vulnerabilities` → **NOSQLI-001**
- `testing-for-xxe-injection-vulnerabilities` → **XXE-001**
- `testing-for-host-header-injection`, `testing-for-email-header-injection` → **HOSTHDR-001**
- `performing-clickjacking-attack-test` → **CLICKJACK-001**
- `testing-cors-misconfiguration` → **HDR-002**
- `performing-security-headers-audit` → **HDR-001**
- `exploiting-jwt-algorithm-confusion-attack`, `performing-jwt-none-algorithm-attack`, `testing-jwt-token-security`, `testing-for-json-web-token-vulnerabilities` → **JWT-001 / JWT-002**
- `testing-oauth2-implementation-flaws`, `exploiting-oauth-misconfiguration`, `configuring-oauth2-authorization-flow`, `detecting-oauth-token-theft`, `performing-oauth-scope-minimization-review` → **OAUTH-001**
- `implementing-api-rate-limiting-and-throttling`, `performing-api-rate-limiting-bypass`, `implementing-api-abuse-detection-with-rate-limiting` → **RATE-001 / PAGINATION-001**
- `exploiting-race-condition-vulnerabilities` → **RACE-001**
- `exploiting-server-side-request-forgery`, `performing-blind-ssrf-exploitation` → **SSRF-001**
- `exploiting-insecure-deserialization` → **FLOOR-A08**
- `implementing-secret-scanning-with-gitleaks`, `implementing-secrets-scanning-in-ci-cd`, `detecting-aws-credential-exposure-with-trufflehog` → **SEC-LEAK-001 / CISEC-001**
- `performing-sca-dependency-scanning-with-snyk`, `scanning-containers-with-trivy-in-cicd`, `analyzing-sbom-for-supply-chain-vulnerabilities` → **DEP-001 / CISEC-001**
- `integrating-sast-into-github-actions-pipeline`, `integrating-dast-with-owasp-zap-in-pipeline`, `detecting-supply-chain-attacks-in-ci-cd` → **CISEC-001**
- `configuring-tls-1-3-for-secure-communications`, `performing-ssl-tls-security-assessment` → **FLOOR-A02**
- `implementing-jwt-signing-and-verification`, `configuring-multi-factor-authentication-with-duo`, `implementing-passwordless-authentication-with-fido2` → **JWT-001 / ACCT-VERIFY-001**
- `detecting-ai-model-prompt-injection-attacks` → **LLM-INJ-001**
- `auditing-terraform-infrastructure-for-security` → **(infra; DEC/deploy-ops)**
- `performing-graphql-security-assessment`, `performing-graphql-depth-limit-attack`, `performing-graphql-introspection-attack` → **GRAPHQL-001 (queued template)**

**Catalogued (offensive / detection / DFIR variants — pull on demand, not engine checks):**
the remaining ~110 app-adjacent skills (e.g. `detecting-api-enumeration-attacks`,
`hunting-credential-stuffing-attacks`, `performing-web-application-penetration-test`,
`conducting-api-security-testing`, `implementing-cloud-waf-rules`,
`implementing-ddos-mitigation-with-cloudflare`, `implementing-hashicorp-vault-dynamic-secrets`,
`implementing-mtls-for-zero-trust-services`, `performing-threat-modeling-with-owasp-threat-dragon`,
`implementing-dmarc-dkim-spf-email-security`, `implementing-envelope-encryption-with-aws-kms`, …)
— these are detection/ops/offensive procedures. Pull the specific one when a task calls
for it; they don't belong in a pass/fail app-hardening gate.

The other **568 skills** (forensics, malware analysis, threat hunting, IR, red team,
OT/ICS, mobile, network) are out of bedrock's app-hardening scope and live in the corpus
for when an investigation needs them.
