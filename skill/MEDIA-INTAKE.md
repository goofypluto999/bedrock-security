# Media Intake — turning videos / shorts / images into enforced checks

> You'll feed me security content in raw form (a video, a short, a screenshot, a
> slide, a thread). It's valuable but **not yet in the right format and not fully
> developed**. This file is the contract that turns each piece into a permanent,
> enforced part of the system — so nothing you send is lost, hand-waved, or left as
> a loose suggestion.

---

## How to send

Drop the file(s) or paste the link/text, and (optionally) one line of what caught
your eye. Staging area (never committed — it's gitignored; may be large or sensitive):

```
_intake/
  media/            <- drop videos/shorts/images/screenshots here (or just paste)
  INTAKE-LOG.md     <- the running log; every item gets an outcome row (committed)
```

You do **not** need to format anything. Raw is fine. Extraction is my job.

---

## The pipeline (what I do with each item — every time)

1. **EXTRACT.** Pull the actual security claim/technique out of the media —
   transcribe the relevant part of a video, OCR/read a screenshot, read the slide.
   State, in one or two sentences, *the underlying control or attack* it's really about.
2. **CLASSIFY.** Decide what it becomes (it's exactly one of these — see next section).
3. **GROUND.** Find the **oracle** (OWASP / CWE / RFC / ASVS id) the technique maps to.
   If a tip can't be anchored to an external authority or a concrete falsifiable
   property, I flag it as "opinion/heuristic" and we decide whether it earns a check.
   No oracle, no silent promotion.
4. **FORMALIZE.** Write it up in the exact shape the system needs (a registry record,
   a template, a reference-doc section, or a refinement) — applicability, proof
   method, pass criteria, fail action.
5. **INTEGRATE + VALIDATE.** Slot it into the right `domain` + `phase`, then
   **re-validate**: parse the registry, run `sweep.py` so a bad pattern or duplicate
   id surfaces immediately. A check isn't "added" until the engine still runs clean.
6. **LOG.** Append one row to `_intake/INTAKE-LOG.md` with the outcome. **Nothing is
   dropped silently** — even "already covered by JWT-002" gets logged as a row.

---

## What a single item can become (the classification)

| Outcome | When | Where it lands |
|---|---|---|
| **New check** | A distinct control/attack not yet in the registry | a new `checks:` record in `registry.yaml` |
| **Refinement** | A sharper failure mode / better proof for an existing check | edit the existing record + its reference section |
| **New proof template** | An existing check gains a runnable test in a stack it lacked | `templates/<stack>/…` + wire into the record + `INDEX.md` |
| **New domain/cluster** | A whole area we don't cover (e.g. mobile, container, IaC) | add to `meta.domains` + seed its first checks |
| **Methodology / philosophy** | A way-of-testing insight, not a single check | a section in `references/security-testing-methodology.md` or `SKILL.md` |
| **Floor item** | A basic that belongs in the Tier-0 floor | a `FLOOR-*` record (ref `skill://owasp-top-10` etc.) |
| **Duplicate / already covered** | The system already enforces it | **no change** — but logged, with the id that covers it |

One media item occasionally yields more than one outcome (e.g. a new check *and* a
methodology note). That's fine; log each.

---

## The record template (what I fill for a "new check")

```yaml
  - id: <DOMAIN-NNN>                 # e.g. CACHE-001, MOBILE-003
    title: <one line, falsifiable>
    domain: <one of meta.domains>
    phase: <frame|static|adversarial|decision>
    severity: <critical|high|medium|low|info>
    method: <inventory|static-scan|adversarial-test|decision>
    oracle: [<OWASP/CWE/RFC/ASVS id>]
    applicability:
      question: <when does this apply?>
      auto_probe:
        type: <grep_present|antipattern|file_present|command|manual>
        patterns: ['<regex or glob>']
        langs: [<langs>]
    proof:
      description: <how to PROVE it — the test or live probe>
      templates: { <stack>: templates/<stack>/<file> }   # if adversarial-test
    pass_criteria: <the bar>
    fail_action: <what FAIL means + fix direction>
    ref: <references/<doc>.md#anchor  or  source: the media you sent>
    source: <"intake YYYY-MM-DD: <your one-liner / link>">   # provenance
```

Every media-derived check carries a `source:` line so we always know which video/
short/image it came from.

---

## The standard each new check must meet (so the system stays rigorous)

A new check is only as good as its proof. Before it's accepted it must have:
- an **oracle** (or an explicit "heuristic, no oracle" tag we both agreed to),
- a **falsifiable** `pass_criteria` (a sentence a test could prove false),
- an **applicability** rule (so it's never a blanket "always run, always nag"),
- a **proof method** that produces an artifact — not "review it and confirm".

That's the same bar the existing 52 checks meet. Media gets *developed up to* this
bar; it doesn't get to lower it.

---

## Ready

Send the first batch whenever. For each, I'll reply with: the extracted control, its
classification, the oracle, the formalized record/template, the re-validation result,
and the log row. Then it's enforced for every sweep from then on.
