# Secrets, Env & Secure Ops — storage, the fail-open/closed framework, deploy footguns

> The operational layer: where secrets live, how controls should fail, and the
> deploy/ops mistakes that bite after the code is already secure.

## 1. The fail-open vs fail-closed decision framework

Every security control has a behavior when *the control itself* errors or its
backing store is unavailable. Choosing wrong is a top cause of either outages
(fail-closed where you shouldn't) or silent exposure (fail-open where you
shouldn't). Decide deliberately, per control:

| Control type | When the control fails, should the request… | Why |
|---|---|---|
| **Authentication** | …be **DENIED** (fail closed) | Can't verify identity → must not proceed. |
| **Authorization** | …be **DENIED** (fail closed) | Can't confirm permission → deny. |
| **Input validation / injection guard on a write** | …be **DENIED** (fail closed) | Letting unvalidated data hit a mutation is worse than rejecting. |
| **Rate limiter** | …be **ALLOWED** + alert (fail open) | It's defense-in-depth; a limiter outage shouldn't 500 the whole API. |
| **Login lockout** | …be **ALLOWED** + alert (fail open) | A lockout-store bug must not deny *all* logins. |
| **LLM output scrub / PII mask** | …**return original** + alert (fail open) | A scrub bug must not blank legitimate responses. |
| **LLM input injection scan** | …be **ALLOWED** + alert (fail open) | Same: a scanner bug shouldn't block real users. (Accept the small exposure window; you log it.) |
| **Audit logging** | …**proceed** + best-effort log (fail open) | The user action shouldn't fail because the audit sink hiccuped — but the gap must be detectable. |

**The principle:** *boundary controls that establish trust fail closed; layered
defenses that reduce risk fail open.* Write the decision in a comment next to
each control. An accidental fail mode is a latent incident.

## 2. Secrets & environment management — do / don't

**Do:**
- Store secrets in the platform's secret manager / env-var store (the host's
  encrypted config), injected at runtime. Read via `os.environ` / equivalent.
- Keep **separate secrets per environment** — dev, staging, prod each have their
  own keys, DB URLs, JWT secret. Dev tokens must be cryptographically incompatible
  with prod (different signing secret) so a leaked dev token is useless against
  prod.
- Rotate on exposure. Treat any secret that touched a chat, a screenshot, a log,
  or a git history as compromised — rotate it, don't reason about whether it
  "really" leaked.
- Commit a `.env.example` with **keys only, no values**.
- Add a secret-scanning pre-commit hook (gitleaks/trufflehog) so a key never
  reaches history in the first place.

**Don't:**
- ❌ Commit `.env`, credentials, or keys — add them to `.gitignore` **before** the
  first commit, not after (git history is forever; a later removal doesn't undo
  exposure).
- ❌ Put secrets in client-visible places: frontend bundles, URLs/query params
  (they land in server logs, browser history, referrer headers), error messages,
  or LLM prompts/outputs.
- ❌ Echo a submitted secret back in a validation error (CWE-532) — sanitize
  validation errors to field+message+type only.
- ❌ Hardcode a fallback secret in code "for dev". A hardcoded default JWT secret
  shipped to prod = total auth bypass.
- ❌ Reuse one secret across services/environments.
- ❌ Log full request bodies on auth endpoints (they contain passwords/tokens).

**If a secret is pasted into a chat / shared with an assistant:** never store,
echo, or reuse it. Direct the owner to rotate it immediately. The only safe
assumption is that it's now compromised.

## 3. Deploy & ops footguns (the post-code-secure mistakes)

These don't show up in code review — they bite at deploy time:

- **Wrong account / wrong project link.** Multi-account CLIs (cloud, container
  platforms) silently operate on whatever account the local token belongs to.
  Symptom: auth "works" (`whoami` succeeds) but you can't see the project, or
  worse, you deploy to the *wrong* project. *Mitigation:* before any deploy,
  verify the linked project/account explicitly (`<cli> status` / `whoami`) and
  confirm it matches the intended target. Re-login as the correct account if the
  workspace shows empty/foreign projects. (No damage from a wrong-account
  read/login — but verify before any *write*/deploy.)
- **Stale CLI auth tokens.** Refresh tokens expire; a deploy fails mid-incident
  because the CLI quietly logged out. Keep the CLI updated; know the
  `--browserless`/pairing-code login path for when the browser OAuth callback
  fails.
- **Pushing to the source-of-truth branch ≠ deploying.** If the platform deploys
  from a CLI image push (not git auto-deploy), a `git push` to `master` changes
  *nothing* in prod. Know your actual deploy mechanism. Conversely, if it *is*
  git-auto-deploy, a push IS a prod change — treat it as one.
- **Local-ahead-of-remote divergence.** A "production" working folder can drift
  ahead of the remote branch (commits that were deployed but never pushed).
  Reconcile before merging new work — a blind merge produces conflicts or silently
  reverts deployed fixes. Always `fetch` + inspect `git log remote..local` and
  `local..remote` before merging.
- **Multi-worker assumptions.** Anything stored in process memory (rate-limit
  counters, lockout state, caches) does NOT survive across workers or restarts.
  If a control's correctness depends on a shared count, it needs a shared store
  (Redis) — verify it's actually wired in prod, not just configured.
- **Storage backend hard-fail.** A control pointed at Redis/DB that *raises* on
  outage can take down every route that uses it. Enable graceful degradation
  (`swallow_errors` + in-memory fallback) for the fail-open controls.

## 4. Pre-deploy security gate (run before every prod deploy)

- [ ] Secrets are in the platform store, none added to the repo this change.
- [ ] `.gitignore` covers `.env*`, key files, local config. Secret-scan clean.
- [ ] New controls have a documented fail-open/closed decision + a kill switch.
- [ ] The security test suite is green **in a clean batch run** (not just isolation).
- [ ] You've confirmed the **deploy target** (account + project + branch + actual
      deploy mechanism) before pushing the button.
- [ ] You know the **rollback** command for this deploy (last-known-good commit +
      redeploy) and the **kill-switch env flags** for any risky new control.
- [ ] Post-deploy smoke is scripted: health check + one assertion per shipped
      security contract (BOLA→404, quota→402, lockout→429+Retry-After, guard→400),
      plus a regression pass that the *existing* contracts still hold.

## 5. Incident-time muscle memory

When something's wrong in prod:
1. **Mitigate before diagnosing** if users are exposed — flip the kill switch /
   roll back to last-known-good first, investigate second.
2. **Distinguish "your change" from "platform outage."** Probe the dependency
   directly (is the DB/Redis/host up?) before assuming your deploy broke it.
   Behavioral probes beat guessing (e.g. curl the contract, don't read tea leaves).
3. **Watch for recovery with a poller**, don't hammer-refresh — a script that
   polls the health endpoint and notifies on green frees you to work.
4. **Capture the incident + the fix in a durable note** (not just the chat) so the
   same footgun is a 30-second fix next time, not a 20-minute re-discovery.
