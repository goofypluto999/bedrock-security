# More Controls — the second-order topics that round out the playbook

> Companion to `hardening-playbook.md`. Each is a control that generic checklists
> under-cover but that bites real products. Same format: failure mode → fix →
> oracle.

---

## 1. SSRF — Server-Side Request Forgery (CWE-918, OWASP A10:2021)

**Where it hits:** anywhere your server fetches a URL the user influenced —
webhook target registration, "import from URL", avatar-by-URL, link-preview /
unfurl, and **LLM/RAG that reads a user-supplied URL or follows a link inside a
document** (indirect injection's evil twin). The attacker points it at internal
addresses to reach cloud metadata, internal admin panels, or localhost services.

**Failure mode generic advice misses:** blocking `localhost`/`127.0.0.1` is not
enough. Attackers reach internal targets via:
- the cloud metadata IP `169.254.169.254` (steals instance credentials),
- private ranges `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `::1`, link-local,
- DNS rebinding (a hostname that resolves public on validation, private on fetch),
- redirects (you validate URL A, it 302s to an internal URL),
- IPv6/decimal/octal/`0x` encodings of the same addresses, and `[::ffff:127.0.0.1]`.

**Fix:**
- Validate **after DNS resolution**, against the *resolved IP*, and re-validate on
  every redirect hop (or disable redirects). Reject any IP in private/loopback/
  link-local/metadata ranges.
- Allow-list schemes (`https` only), ports, and ideally destination hosts.
- Pin the resolved IP and connect to *that* (defeats rebinding) — resolve once,
  validate, connect to the validated address.
- Block the metadata endpoint explicitly; on cloud, prefer IMDSv2 + hop-limit 1.
- Run outbound fetchers with no ambient cloud credentials where possible.

**Test:** attempt fetches to `169.254.169.254`, `127.0.0.1`, a private IP, and a
public URL that redirects to a private one → all rejected.

---

## 2. Webhook signature verification (inbound)

**Where it hits:** payment/provider webhooks (Stripe `whsec_…`, GitHub, etc.).
Generic advice covers *scrubbing* a leaked `whsec_` (see CWE-532) but not the more
important thing: **verifying** that an inbound webhook actually came from the
provider before acting on it. An unverified webhook endpoint lets anyone POST
"payment succeeded" and unlock paid features.

**Fix:**
- Verify the provider's HMAC signature over the **raw request body** (not the
  parsed/re-serialized JSON — re-serialization changes bytes and breaks the HMAC).
  This often means reading the raw body *before* any JSON middleware touches it.
- Use a **constant-time** comparison for the signature (see §3).
- Enforce the provider's **timestamp tolerance** to defeat replay (reject
  signatures older than ~5 min).
- Make the handler **idempotent** by event id (see §4) — providers retry, and you
  must not double-apply.
- Don't rate-limit the webhook so tightly that the provider's documented burst is
  starved → fail closed on signature, but generous/no limiting on volume.

**Test:** a request with a bad/missing signature → 400; a replayed old-timestamp
signature → rejected; a duplicate event id → processed once.

---

## 3. Timing-safe comparison

**Where it hits:** comparing any **secret** the attacker can submit and retry —
API keys, password-reset/verification tokens, webhook HMACs, TOTP codes, signed
cookie values. A normal `==` / string compare short-circuits on the first
differing byte, so response time leaks how many leading bytes were correct →
byte-by-byte recovery.

**Fix:** use a constant-time compare: `hmac.compare_digest` (Python),
`crypto.timingSafeEqual` (Node), `subtle.ConstantTimeCompare` (Go),
`MessageDigest.isEqual` is **not** constant-time in old JVMs — use
`MessageDigest.isEqual` only on modern JDKs or a dedicated routine. Compare hashes
of equal length (or the routine itself can leak length).

**Test:** verify the comparison path uses the constant-time primitive (code
review; timing tests are flaky in CI — assert the *call*, not the timing).

---

## 4. Idempotency keys

**Where it hits:** any non-idempotent operation a client may retry — payments,
order creation, sending an email/SMS, provisioning. Network retries, double-clicks,
and provider webhook re-deliveries cause duplicates: double charges, double sends.
This is the companion to the atomic-debit section.

**Fix:**
- Accept a client-supplied `Idempotency-Key` header (or derive a stable key from
  event id for webhooks).
- Persist `(key → result)` with a unique constraint; on a repeat key, return the
  **stored result** instead of re-executing. The unique constraint + transaction
  makes the dedupe atomic under concurrency (two simultaneous retries: one
  inserts, the other hits the constraint and reads the result).
- Scope keys per-tenant and expire them on a sensible window.

**Test:** fire the same idempotency key twice (sequentially AND concurrently) →
the side effect happens exactly once; both responses match.

---

## 5. Request-size & decompression limits (DoS surface)

**Where it hits:** any endpoint accepting a body, an upload, or compressed input.
Generic "validate input" doesn't cap *size* or *complexity*.

**Failure modes:** multi-GB body exhausts memory; deeply-nested JSON
(`{"a":{"a":{...}}}`) blows the parser stack; a "zip bomb" / highly-compressible
gzip body expands to gigabytes after decompression; a multipart upload with a
huge declared file.

**Fix:**
- Cap max body size at the edge (reverse proxy/LB) AND in the app.
- Bound JSON nesting depth and array/object element counts.
- Cap **decompressed** size, not just the compressed size — stop decompression
  once the output exceeds a limit.
- Stream large uploads to storage with a hard size cap; never buffer wholesale.
- Pair with the bounded-regex rule (no ReDoS — see `ai-llm-security.md`).

**Test:** oversized body → 413; over-deep JSON → 400, not a 500/crash.

---

## 6. Dependency / supply-chain hygiene

**Where it hits:** your `node_modules`/`site-packages` are most of your attack
surface and none of your code. Generic advice stops at "keep dependencies
updated."

**Fix:**
- **Commit lockfiles** (`package-lock.json`, `poetry.lock`, `requirements.txt`
  pinned) — reproducible, auditable installs.
- Run `npm audit` / `pip-audit` / `osv-scanner` in CI; gate on **high/critical**.
  Distinguish **dev-only** vulns (build tools — lower prod risk) from **runtime**
  vulns (shipped to users — higher). A path-traversal in your bundler's dev server
  is not the same risk as a prototype-pollution gadget in a runtime lib.
- Secret-scan in pre-commit (gitleaks/trufflehog) so a key never enters history.
- Pin GitHub Actions/CI actions to a commit SHA, not a moving tag.
- Watch for typosquats and unexpected new transitive deps on update.

**Test:** CI fails on a newly-introduced high/critical advisory; lockfile drift is
detected.

---

## 7. Audit-log integrity

**Where it hits:** you have an audit log (the fail-open table assumes one). But an
audit log an attacker can **edit or delete** after the fact is theatre — and
during an incident a tamperable log can't be trusted.

**Fix:**
- Audit records are **append-only** — no UPDATE/DELETE grants on the table to the
  app role; writes only.
- Ship audit events to a **separate sink** the app can't rewrite (a log pipeline,
  WORM storage, or a different DB/account) so compromising the app doesn't let the
  attacker scrub their tracks.
- For high-assurance, **hash-chain** entries (each row includes a hash of the
  previous) so deletion/edits are detectable.
- Retain audit logs even when you delete user data for GDPR — Article 17(3)(b)
  permits retention for legal-obligation purposes; scrub PII from the audit
  *payload* but keep the event record.

**Test:** the app's DB role cannot UPDATE/DELETE audit rows; a deleted user's
audit events still exist (PII-scrubbed).

---

## 8. CSRF & cookies for SPAs (the nuance the "floor" skips)

**Where it hits:** the floor says "use CSRF tokens", but the right answer depends
on your auth transport:
- **Bearer token in an `Authorization` header** (typical SPA): not
  CSRF-vulnerable, because the browser doesn't auto-attach it cross-site — the JS
  must add it, and same-origin policy stops a malicious site from reading/adding
  it. CSRF tokens are redundant here; **the risk shifts to XSS** (an XSS can read a
  token from `localStorage`). Mitigate XSS (CSP, output encoding) rather than
  adding CSRF tokens.
- **Session cookie**: IS CSRF-vulnerable. Set `SameSite=Lax` (or `Strict`),
  `Secure`, `HttpOnly`, AND use CSRF tokens (double-submit or synchronizer) for
  state-changing requests. `SameSite` alone is defense-in-depth, not a complete
  CSRF defense (it has cross-browser edge cases and doesn't cover same-site
  subdomains).
- Decide **cookie vs bearer** deliberately; don't mix auto-attached cookies with
  no CSRF protection.

**Test:** a state-changing request forged cross-origin without the token/with a
mismatched SameSite context → rejected; bearer-auth routes don't accept ambient
cookies.

---

## 9. Where these slot into the gates

Add to the SKILL.md completion gates when relevant to your app:
- [ ] Any user-influenced server-side fetch validates the **resolved IP** against
      private/metadata ranges and re-validates on redirect (SSRF).
- [ ] Inbound webhooks verify a **constant-time HMAC over the raw body** with a
      replay window, and are idempotent by event id.
- [ ] All submitted-secret comparisons use a **constant-time** primitive.
- [ ] Non-idempotent operations accept/derive an **idempotency key** and apply the
      side effect exactly once under concurrent retry.
- [ ] Body size, JSON depth, and **decompressed** size are bounded.
- [ ] CI gates on high/critical dependency advisories; lockfiles committed; secrets
      scanned pre-commit.
- [ ] Audit log is append-only / separately-sinked and survives user deletion.
- [ ] CSRF posture matches the auth transport (bearer → fight XSS; cookie →
      SameSite + CSRF tokens).
