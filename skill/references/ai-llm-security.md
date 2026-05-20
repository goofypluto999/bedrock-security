# AI / LLM Security — guardrails, prompt injection, and cost-aware escalation

> For any app that sends user-influenced text to an LLM (chatbots, agent
> simulations, "parse this with AI", RAG). Oracle: OWASP Top 10 for LLM Apps
> (LLM01 Prompt Injection, LLM02 Insecure Output Handling, LLM06 Sensitive
> Information Disclosure).

## 1. The two attack directions

1. **Input → model (prompt injection / jailbreak).** User text manipulates the
   model into ignoring its instructions, revealing its system prompt, adopting an
   unrestricted persona, or producing disallowed content. Includes *indirect*
   injection (malicious instructions inside a document/URL the model later reads).
2. **Model → user (insecure output).** The model emits something harmful: a
   secret it was fed, fabricated-but-real-looking PII, executable markup, or
   content that's unsafe to render/execute downstream.

You need a guard on **both** directions.

## 2. The cost-aware escalation ladder (pick the cheapest layer that meets the threat)

Guardrails span a huge cost range. Don't reach for the heavy option first.

| Tier | What | Cost | Catches |
|---|---|---|---|
| 0 | Schema limits (max_length, type, enum) | ~0 | oversized payloads, type confusion |
| 1 | **Pure-regex/heuristic input scan + output scrub** | ~µs, $0, no deps | the common naive injections + secret/PII formats (~60-80%) |
| 2 | System-prompt hardening + topic constraint | ~0 extra | off-topic abuse, weak persona override |
| 3 | A small dedicated classifier model (local or cheap API) | +1 small call | subtler injection, toxicity |
| 4 | Managed guardrail framework (e.g. NeMo Guardrails) self-check in+out | **+2 LLM calls/request**, latency, ops | sophisticated/obfuscated injection, fact-checking, dialog rails |

**Rule:** Tier 1 + 2 is the right default for most products. Escalate to Tier 3/4
only when the threat model justifies the per-request cost — e.g. you're handling
regulated data, you've seen real sophisticated attacks, or the business value per
request is high enough to absorb 2× the LLM spend. **Document the escalation
trigger** so it's a decision, not a default.

A control that adds 2 LLM calls and a second of latency to *every* request will
get disabled the first busy day. Cheap-and-80% that stays on beats
expensive-and-99% that gets removed.

## 3. Tier-1 guard — the pure-Python pattern (no ML deps, no extra LLM calls)

Two functions, applied at the **user-facing LLM surfaces only**:

### `scan_input(text) -> flagged?`
Regex/heuristic detection of injection. The key to **low false positives**: require
the manipulation *verb* paired with an instruction/system *object*, so legitimate
domain text doesn't trip it.

- ✅ flag: `ignore … (previous|prior|above) (instructions|rules|prompt)`
- ✅ flag: `(reveal|show|print) … (system prompt|your instructions)`
- ✅ flag: `you are now … (DAN|jailbroken|unrestricted|no rules)`
- ✅ flag: `(enable|activate) (developer|god|admin) mode`
- ✅ flag: `(bypass|disable) … (safety|filters|guidelines|guardrails)`
- ✅ flag: line starting with `system:` / `assistant:` (fake conversation-turn)
- ✅ flag: chat-template tokens `<|im_start|>`, `<<SYS>>`, `[INST]`
- ❌ do NOT flag bare verbs: "ignore our previous pricing strategy", "act as the
  premium option", "developer-focused segment" — these have no instruction object,
  so a verb-only match would false-positive on real business text.

On flag → reject with **400 + a clean message**, before any LLM dispatch (saves
the token spend on a malicious request too).

### `scrub_output(text) -> cleaned`
Run on model output before returning to the user:
- Reuse the **same secret-scrubber** as your logs (single source of truth) — keys,
  JWTs, bearer tokens, hashes.
- Plus regex PII masks: email, phone, credit-card-shaped digits, SSN. (Names need
  ML/NER and over-mask — skip at Tier 1; that's a Tier-3 reason.)

## 4. Non-negotiable design properties for any guard

- **Fail-open.** A guard exception logs + allows (scan) / returns original text
  (scrub). A bug in the *defense* must never break a paying user's request. (This
  is the opposite of auth, which fails closed — see secrets-and-ops.md.)
- **Kill switch.** `GUARD_ENABLED=false` disables it instantly via env var, no
  redeploy. The first time a guard over-blocks real users, you need an
  off-switch in seconds.
- **Don't guard the hot loop.** Apply guards to the *user-facing* endpoints
  (chat, parse, survey), NOT the internal high-volume model calls (e.g. a
  simulation that makes thousands of agent calls). Those inputs are already
  filtered upstream by the user-facing guard, and per-call overhead × thousands is
  prohibitive. Guard the perimeter, not every interior call.
- **Monitor-mode first (optional).** For a risky rollout, ship the guard in
  log-only mode (detect + log, don't block) to gather real-traffic false-positive
  data, THEN flip to enforce. Costs one env flag.

## 5. What the model's own alignment does and doesn't cover

Modern aligned models often self-refuse the obvious "reveal your system prompt".
That is **not** a substitute for an input guard, because:
- it still *spends the LLM call* on the malicious request (your $),
- it covers the cases the vendor trained on, not your app-specific abuse,
- it's silent — you get no signal/metric that an attack happened.
The input guard blocks pre-dispatch (cheaper), is enforceable/measurable, and is
under your control.

## 6. Testing LLM guards (oracle: OWASP LLM01/LLM02)

- A battery of injection strings → all rejected (400) before dispatch.
- A battery of legitimate domain inputs → all pass clean (false-positive guard).
- Planted secrets/PII in model output → all masked.
- Clean output → returned untouched.
- Kill-switch off → obvious attack passes (proves the switch works).
- Fail-open → force the scanner to raise → request still allowed (proves the
  defense can't take down the product).
- **ReDoS check:** run every regex against a multi-KB adversarial input and assert
  it completes in <1ms. Bounded quantifiers only — no nested unbounded `+`/`*`
  that can catastrophically backtrack. A regex guard that hangs on a crafted input
  is itself a DoS.
