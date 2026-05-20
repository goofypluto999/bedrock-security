# Hardening Playbook — the controls and their non-obvious failure modes

> Each entry: the control, the **failure mode generic advice misses**, the fix,
> and the oracle. Language-agnostic; pseudocode where it clarifies.

---

## 1. Broken Object-Level Authorization (BOLA / IDOR) — and the status-code leak

**Generic advice:** "check the user owns the object."

**What it misses:** *how you deny* matters as much as denying. Returning `403
Forbidden` for an object owned by someone else, but `404 Not Found` for an object
that doesn't exist, leaks existence. An attacker enumerating ids reads the
403/404 differential to map which ids are real — a private oracle.

**Fix:** for "exists but you can't see it", return the **same response as "never
existed"** — same status (`404`), same body, same error text and length. (Match
those three always; timing is a distant fourth — see SKILL.md philosophy #5 — and
not worth chasing for ordinary object authz.) Scope the lookup by
`(owner_id, object_id)` in the query itself, not a fetch-then-check:

```
# WRONG: leaks existence + does an extra round-trip
obj = db.get(Object, id)            # 404 if missing
if obj.owner_id != caller.id:       # 403 if owned by other
    raise Forbidden()

# RIGHT: one scoped query; identical 404 for "missing" and "not yours"
obj = db.query(Object).filter_by(id=id, owner_id=caller.id).first()
if obj is None:
    raise NotFound("Object not found")   # indistinguishable
```

**Test:** identity B requests A's object across *every* read AND write path
(`GET /x/{id}`, export, mutating POSTs like comment/annotate). All must 404.
**Oracle:** OWASP API1:2023; CWE-639.

**Easy miss:** the mutating endpoints. Teams scope GET but forget the POST that
takes an `object_id` in the body. Authz-missing-on-write is *worse* than on read.

---

## 2. Quota / balance race conditions — atomic check-and-debit

**Generic advice:** "check they have enough credits before charging."

**What it misses:** check-then-act is a TOCTOU race. Two concurrent requests both
read `balance = 1`, both pass the check, both debit → balance goes to `-1` and the
user got two things for one credit. A 50ms window is enough under real load.

**Fix:** make the check and the debit a **single atomic conditional UPDATE** and
react to the row count:

```
# Atomic: only debits if the guard still holds at write time
rows = UPDATE accounts
       SET balance = balance - :cost
       WHERE id = :id AND balance >= :cost      -- guard in the WHERE
UPDATE returns affected row count
if rows == 0:
    raise PaymentRequired(402)  -- someone else won the race, or insufficient
```

No row updated → either you had no funds, or you lost the race to a concurrent
debit that consumed them. Either way the result at write-time is "insufficient
funds" — return the denial, and have the client **re-read its balance** rather
than assuming a permanent state (a top-up may have landed between attempts). The
DB's row lock serializes the concurrent writers for you.

**Order matters:** do cheap rejections (auth, tier check, rate limit) BEFORE the
atomic debit so you don't churn the hot row on requests that were going to fail
anyway.

**Status code:** out-of-balance is best modelled as **402 Payment Required**, NOT
403. 403 means "you're not allowed"; 402 signals "you're allowed but out of
funds" — different frontend handling (buy-more vs upgrade-plan). *Caveat:* 402 is
formally "reserved for future use" in the HTTP spec (RFC 9110 §15.5.3, which
obsoletes RFC 7231) — its semantics aren't standardized, so document your usage in
your API contract and keep the body's `detail` explicit. It's a pragmatic,
widely-used choice (Stripe, GitHub), not an RFC-blessed one. Just don't conflate
it with 403.

**Test:** fire the (N+1)th request concurrently against a balance of N → exactly
N succeed. Assert final balance is exactly 0, never negative, never N-2.

---

## 3. Rate limiting — the identifier is the whole game

**Generic advice:** "add a rate limiter, e.g. 20/min."

**What it misses three ways:**

**(a) Keying on a spoofable identifier.** If the limiter keys on the client IP and
you derive IP from `X-Forwarded-For` (XFF), an attacker rotates that header per
request and gets unlimited attempts. XFF is **client-controlled** unless you are
behind a proxy you trust that manages it.

How XFF actually works (this is subtle and widely gotten wrong):
- XFF is built **left-to-right**: the *leftmost* entry is what the first hop
  claims the client was, and **each proxy appends the peer IP it directly saw to
  the right**. So an attacker can stuff arbitrary values on the **left**; only the
  rightmost entries — added by infrastructure you control — are trustworthy.
- The trustworthy client IP is **the (N+1)-th value counting from the right**,
  where **N = the number of trusted proxy hops between your app and the public
  internet**. With exactly one trusted proxy (the common case: a single CDN/LB in
  front of your app), that's the rightmost value. With two trusted hops (CDN →
  platform LB → app) it's the second-from-right. **Do not blindly "take the
  rightmost"** — with 0 trusted hops the rightmost is just your own LB's address,
  and with the wrong N you either trust an attacker value or rate-limit everyone
  as one IP.
- **Prefer the framework's trusted-proxy configuration** (e.g. a
  `TrustedHosts`/`ProxyHeaders`/`trusted_proxies=N` setting, or Werkzeug's
  `ProxyFix(x_for=N)`) over hand-parsing XFF — it encodes N correctly and is
  audited. Hand-rolled XFF parsing is a recurring source of this bug.
- In dev/test (no trusted proxy), **ignore the header entirely** and use the TCP
  peer. Otherwise your tests "pass" while prod is bypassable.
- For authenticated routes, key the limiter on the **authenticated identity**
  (user/tenant/api-key), falling back to IP only for anonymous traffic. A
  composite key: `user:<id>` if a valid token is present, else `apikey:<k>`, else
  `ip:<addr>`. This sidesteps most XFF risk for logged-in abuse entirely.

**(b) Per-worker counters.** In-memory limiter storage is per-process. With W
worker processes, the effective limit is `limit × W` because each worker counts
independently. *Fix:* back the limiter with a **shared store (Redis)** in
production so all workers share counters. Verify: the documented limit must hold
cluster-wide, not per-worker.

**(c) Hard-fail when the shared store is down.** If the limiter raises when Redis
blips, every rate-limited route 500s — the *defense* took down the *product*.
Rate limiting is defense-in-depth, so **fail open**: degrade to per-worker
in-memory counters (or no limiting) + alert, rather than 500. (Auth is the
opposite — fail closed.) **Be honest that this is an accepted degradation, not a
clean fix:** during the Redis outage you're back to the `limit × W` per-worker
bypass from (b). That's the right trade (availability over a tightened limit for a
defense-in-depth control) but name it, alert on it, and make sure a *primary*
control (auth, the atomic debit) still holds while the limiter is degraded.

**(d) Missing `Retry-After`.** A 429 without `Retry-After` is hostile to honest
clients and non-compliant. Emit `Retry-After: <seconds>` (RFC 6585 §4).

**Test:** rotate `X-Forwarded-For` across the limit window → still throttled on
the authed identity. **Oracle:** OWASP API4:2023.

---

## 4. Anti-brute-force — per-account lockout, placed and shaped right

**Generic advice:** "lock the account after N failed logins."

**What it misses:**

- **Placement:** the lockout check must run **before** the expensive password
  hash (bcrypt/argon2 are ~250ms by design). Otherwise an attacker still pegs your
  CPU even while "locked out". Gate on the counter first, hash only if not locked.
- **Key:** lock on the **email/identity**, not just IP — a distributed
  credential-stuffing attack uses many IPs against one account. (Keep the per-IP
  limiter too; they're complementary layers.)
- **Window:** a sliding window (N failures per T minutes), not a permanent lock —
  permanent locks become a DoS vector against legitimate users.
- **Fail-open:** if the lockout store errors, allow the attempt + log. A lockout
  bug must not deny all logins.
- **Shared store in prod:** same per-worker problem as rate limiting — use Redis
  so the counter is cluster-wide.
- **DoS awareness:** per-account lockout *enables* griefing — an attacker spams
  wrong passwords to lock out a real user. This is an accepted ASVS V2.2.1
  trade-off (lockout beats no-lockout), but mitigate with a CAPTCHA escalator
  before lockout when the product warrants it. Document the trade-off.
- **Test gotcha:** test with **valid-shaped** wrong passwords. If your test uses a
  7-char password against an 8-char minimum, input validation 422s it and it never
  reaches the lockout counter — your test silently proves nothing.

**Oracle:** OWASP API4:2023, OWASP ASVS V2.2.1.

---

## 5. JWT hardening (RFC 8725 BCP)

**Generic advice:** "use JWTs for auth."

**What it misses — the decode-time hardening:**
- **Reject `alg: none`.** Pin the allowed algorithm(s) explicitly at decode.
- **Reject algorithm confusion** (RS256 token replayed as HS256 with the public
  key used as the HMAC secret). Pin the *exact* expected alg, not a family.
- **Require `exp`.** A JWT with no expiry never dies. Explicitly require the claim
  at decode so a missing-`exp` token is *rejected*, not treated as eternal. The
  knob is library-specific and easy to get wrong — PyJWT:
  `options={"require": ["exp"]}` (older: `require_exp=True`); jose/jsonwebtoken
  variants differ and some do NOT reject missing-exp by default even with verify
  on. Confirm with a test (a hand-crafted token with no `exp` must 401), don't
  assume the default.
- **Validate `aud` / `iss`** when using third-party tokens (SSO id_tokens):
  confirm the audience is *your* client_id (confused-deputy / token-reuse defense)
  and that `email_verified` is true before trusting an email claim.
- **Revocation:** plain JWTs can't be revoked. If you need logout/"revoke other
  sessions", back the JWT with a server-side session/jti store and check
  revocation on each request.
- **Don't put secrets/PII in the payload** — JWTs are signed, not encrypted; the
  payload is base64, readable by anyone.

**Test:** alg=none, alg-confusion, missing-exp, expired, tampered-signature,
aud-mismatch → all rejected with 401.

---

## 5b. Token-purpose confusion — the multi-token / 2FA-bypass class

> Found in a real audit: a HIGH-severity 2FA bypass that five separate reviewers
> (including a strong general code review) missed — only a pass specifically
> tracing *token purpose across the auth flow* caught it. It's subtle, common, and
> devastating, so it gets its own entry.

**The setup:** an app mints several JWT *types* — an **access token**, a
**2FA-challenge token** (the "you passed the password, now do TOTP" interstitial),
a **password-reset token**, an **email-verify token**, a magic-link token, etc.
For convenience they're all signed with the **same secret + same algorithm**, and
several of them carry the user/tenant identity (`sub`, `role`, `user_id`) because
the next step needs it.

**The failure mode:** the general access-token validator
(`decode_token` / `get_current_user`) checks **signature + expiry only — it never
checks what the token is *for*.** So a token minted for one purpose is accepted as
another. The worst case:

- User has 2FA on. Attacker has the password (the *exact* threat 2FA exists to
  stop — phishing, reuse, breach).
- Attacker logs in → server returns `200 {requires_2fa: true, challenge_id: <JWT>}`.
- The `challenge_id` is signed with the auth secret and carries a valid `sub`.
- Attacker sends `Authorization: Bearer <challenge_id>` to any protected route.
- The access validator sees a valid signature + unexpired token with a `sub` →
  **authenticates the attacker as the full user. TOTP entirely skipped.**

The same bug lets a password-reset or email-verify token act as a session, or a
low-scope token act as a high-scope one. A docstring that *says* "a `purpose`
claim prevents this" is worthless if the validator doesn't actually read it.

**Fix — make purpose a hard, checked invariant:**
- **Stamp every token with a `purpose`/`typ` claim** (`access`, `2fa_challenge`,
  `pw_reset`, `email_verify`, …).
- **Each consumer requires its own purpose.** The access path rejects any token
  whose purpose isn't `access`; the 2FA endpoint requires `2fa_challenge`; etc.
  Don't just check the special path — the *access* path must reject the special
  tokens.
- **Non-breaking rollout:** if existing access tokens have *no* purpose claim and
  every special token *does*, the immediate, zero-logout fix is: in the access
  path, reject any token where `purpose` is present and != `access`. (Access
  tokens have no purpose → still accepted; challenge/reset tokens are rejected.)
  Then, as a follow-up, start stamping `purpose:"access"` and require it.
- **Stronger:** sign different token classes with **different secrets/keys** so a
  cross-class token fails signature verification outright. Belt-and-braces over
  the claim check.
- **Bind to a session where it matters:** if your revocation check is a no-op when
  a `jti` is absent (a common "legacy token" fallback), a `jti`-less special token
  also skips revocation — another reason the purpose check must be explicit.

**Test (make this a permanent regression):** mint each non-access token type and
send it as a `Bearer` to a protected route → every one must **401**. Add the 2FA
case specifically: complete `/login`, take the `challenge_id`, use it as a Bearer
→ 401, not 200. **Oracle:** OWASP API2:2023 (Broken Authentication); RFC 8725
§3.11 ("use explicit typing" / distinguish token types).

**How to catch this class in review:** grep every JWT-minting site, list the
*purposes*, then grep every `jwt.decode`/validator and confirm each enforces the
purpose it expects. The bug lives in the gap between "we mint 4 token types" and
"the validator checks 1 property (signature)."

---

## 6. Secret leakage in logs / errors / emails (CWE-532)

**Generic advice:** "don't log secrets."

**What it misses:** secrets leak *indirectly* — an exception message that happens
to contain a token, a validation error that echoes the submitted value back, an
alert/email built from `str(exception)`, a 422 body that reflects the bad input
(which was a password). You didn't *intend* to log it; it rode in on an error.

**Fix:**
- A central **scrubber** applied to anything bound for logs/alerts/emails/error
  bodies, with patterns for the high-value formats: provider API keys (`sk_…`,
  `pk_…`, `whsec_…`), JWTs (`eyJ…`), `Bearer …`, cloud keys (`AKIA…`), VCS tokens
  (`ghp_…`), bcrypt hashes (`$2…`), `password=…` / `api_key=…` kv pairs.
- **Sanitize validation errors** — never echo the submitted value back. Return
  field location + message + type, not the offending input (a failed password
  lands in the response body and every downstream log sink otherwise).
- Scrub is **conservative / fail-leak-through, not fail-over-redact** — it targets
  known formats; it must not blank legitimate content. (The cost of over-redaction
  is broken UX; calibrate.)

**Test:** plant a known secret in an input that bubbles into each sink → assert
the sink shows `[REDACTED:…]`, not the secret. **Oracle:** CWE-532.

---

## 7. Security headers + CORS (the quick wins worth verifying)

- `Content-Security-Policy` (lock script-src; avoid `unsafe-inline` where you can),
  `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY` (or CSP
  `frame-ancestors 'none'`), `Strict-Transport-Security`, `Referrer-Policy`,
  `Cross-Origin-Opener-Policy`, `Permissions-Policy`.
- **CORS:** never reflect arbitrary `Origin` with `Allow-Credentials: true`. Pin an
  explicit allow-list. A wildcard `*` with credentials is the classic foot-gun
  (most browsers block it, but misconfig still leaks to non-credentialed reads).
- Serve JSON APIs as `application/json` (not `text/html`) so a reflected payload
  can't execute when the URL is opened directly — this is what makes JSON-only
  round-trips XSS-safe even if you store a `<script>` string.

**Test:** a preflight from an unauthorized origin is rejected; a 4xx error body
serves as `application/json` and contains no stack trace or filesystem path.

---

## 8. Multi-tenant deletion / cascade safety (GDPR Art.17 + API1)

**Generic advice:** "support account deletion."

**What it misses:** a cascade that crosses the tenant boundary. Deleting tenant A
must leave tenant B's data *exactly* unchanged. A foreign-key cascade or a too-broad
`DELETE … WHERE` can wipe shared/sibling rows.

**Test:** seed A and B, delete A, assert B's row counts are byte-identical before
and after and B's objects are still readable.

---

## 9. The ordering rule (cheap rejections first)

Within a request handler, order checks **cheapest-and-most-likely-to-reject
first**, expensive/irreversible last:

1. Schema validation (Pydantic/zod) — rejects malformed instantly
2. Authn (token decode) — cheap
3. Authz / tier / role — cheap
4. Rate limit / lockout — cheap, shared-store read
5. **Then** expensive work: bcrypt, LLM calls, the atomic debit, the DB writes

This minimizes wasted CPU/$ on requests destined to fail and shrinks the race
window on the irreversible step.
