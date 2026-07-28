# PhishLens — Devpost submission copy

Paste-ready text for each Devpost field. Anything in `[[double brackets]]` needs you
to fill it in before submitting. Everything else is accurate to what's actually built —
don't inflate it; the honesty is a feature when a judge opens the repo.

---

## Tagline (one line)

A phishing detector that red-teams itself — and shows you exactly where it breaks.

---

## Elevator pitch (2–3 sentences)

PhishLens scores suspicious emails for phishing risk and explains every point of that
score in plain English. Then it does something no other detector does: it **attacks its
own classifier live**, applying real evasion techniques one at a time to drive a
Critical verdict down to Low — and turns each successful evasion into a concrete
hardening recommendation. It's a detector that proves what it can't catch, instead of
asking you to trust it.

---

## Inspiration

Phishing is still the single most common entry point for breaches, and the tools that
address it split into two disappointing camps: heavyweight enterprise email-security
suites that are expensive and completely opaque about *why* they flagged something, and
naive keyword blockers that any attacker can evade by rewording a sentence.

The thing that bothered us most is that **almost no detection tool is honest about its
own blind spots.** A vendor ships a model with a confidence score and you're expected to
trust it. But every security engineer knows the real question isn't "what does this tool
catch?" — it's "what does this tool *miss*, and what do I need to layer on top?"

So we built the tool that answers that question about itself.

---

## What it does

**1. Explainable phishing scoring.** Paste a message (or drop a real `.eml` file) and
PhishLens returns a 0–100 risk score broken into individual, human-readable indicators —
brand impersonation across ~48 commonly-spoofed brands, homograph/lookalike domains,
suspicious links, urgency and threat language, credential-harvesting phrasing, and more.
Every point of the score is attributable to a named indicator with an explanation. No
black box.

**2. The Adversarial Red-Team Lab — the core innovation.** Give PhishLens a phishing
email and it plays the attacker against itself. A greedy search over a library of
evasion operators — invisible zero-width-character injection, urgency paraphrasing,
threat paraphrasing, sender neutralization, link laundering, greeting personalization —
applies one technique at a time, keeping whichever mutation lowers its own risk score
most. The result is a live, step-by-step descent: our demo phishing email goes from
**93/Critical to 0/Low in five steps**, with each step naming the exact indicator it
defeated.

Then it closes the loop. Every successful evasion is mapped to a specific hardening
recommendation, and the fully-evaded message is **re-scored against the hardened
detector** to prove which attacks PhishLens genuinely defeats versus which are
fundamental limits of content-only analysis. The invisible-character attack is
neutralized — that same message scores 20, not 0, against the hardened engine — because
building this feature is what motivated us to add Unicode normalization to the matcher
in the first place. The attacks that *do* survive are precisely the argument for the
rest of the product's layers.

**3. Raw `.eml` header forensics.** Drag a real email file in and PhishLens reads the
evidence pasted text can't carry: the receiving mail server's own SPF/DKIM/DMARC verdicts
from `Authentication-Results`, `Return-Path` and `Reply-To` vs `From` domain mismatches,
and the full `Received:` delivery-hop chain. Our sample spoofed email hits 100/Critical
with 11 distinct indicators.

**4. Safe link redirect tracer.** For any link in a message, trace where it *actually*
goes, hop by hop, server-side — the user's browser never touches the destination.
Because "fetch an attacker-chosen URL on the server" is a textbook SSRF risk, every hop's
hostname is resolved and blocked if it points at a private, loopback, or cloud-metadata
address, with a hard cap on redirect count.

**5. Incident reports and alerting.** Every scan produces a printable/PDF-able incident
report. High and Critical scans fire a Slack-compatible webhook, so a security team sees
the alert where they already work.

**6. Multi-tenant dashboard.** Scan history, risk distribution, and top indicators
scoped per organization.

---

## How we built it

**Stack:** Next.js 16 (App Router) with React 19, TypeScript, and Tailwind v4 for the
web app; a FastAPI service in Python for the domain-intelligence layer; Node's built-in
test runner via `tsx` for the test suite.

**Architecture — the part we're most deliberate about.** The core scoring engine is
pure, dependency-free TypeScript functions: an email in, a scored indicator list out.
That purity is what makes the Red-Team Lab possible at all — the adversary module calls
the same `analyze()` the product uses, with a `hardened` flag to toggle between the
production detector and a naive baseline, so the attack results are honest rather than
theatrical. It's also what makes the engine trivially unit-testable (17 tests covering
scoring, header forensics, and adversarial behavior).

**Every external dependency is optional and fails soft.** The Claude API layer that
generates plain-English summaries, the Python enrichment service, and the alert webhook
are each bounded by their own timeout and degrade to "the app still works, and tells you
what's unavailable" rather than failing a scan. You can clone the repo and run the whole
thing with zero API keys.

**Security in the tool itself.** Building a link tracer means building an SSRF machine
if you're careless, so hostname resolution and private-range blocking gate every hop.
The API routes are rate-limited, request bodies are size-capped, and JSON parse failures
return clean 400s.

---

## Challenges we ran into

**Making the adversary honest rather than a demo trick.** The easy version of this
feature is a scripted animation that always produces the same pretty descent. We wanted
a real greedy search where each operator is genuinely evaluated against the live scorer
and only kept if it actually reduces the score — which means the Lab can, correctly,
fail to fully evade a message. Getting the operator library to produce meaningful
mutations (semantically equivalent, visually plausible) rather than word salad took
several iterations.

**The tool found a real bug in itself.** The first version of brand impersonation only
fired when a brand name appeared in the sender's *display name*. Testing against
realistic phishing revealed the far more common pattern — a brand-free display name with
the brand stuffed into the domain (`paypal-secure-verify.com`) — sailed straight through.
Same story with homograph domains: an early sender-parsing regex was ASCII-only, which
silently *destroyed* the Cyrillic characters we needed to detect a lookalike domain.

**Zero-width characters are hostile to source code.** The invisible-character evasion
operator required literal zero-width Unicode in the codebase, which is genuinely
dangerous — invisible characters in source are unreviewable. We had to rewrite those
constants as explicit `​`-style escapes so every reviewer can see exactly what's
there.

**Being disciplined about scope.** With a broad problem space it's tempting to add
surface area. We deliberately kept the interface stripped down — plain borders, system
fonts, functional color only — so the engineering carries the project instead of visual
noise.

---

## Accomplishments that we're proud of

- **A detection tool that publishes its own failure modes.** The Red-Team Lab is the
  thing we haven't seen anyone else do, and it reframes the product from "trust our
  score" to "here's exactly where our score breaks and what to layer on top."
- **The feature improved the product it was testing.** Unicode normalization exists in
  the matcher today specifically because the adversary exploited its absence. That's the
  attack → finding → defense loop working end to end, in one afternoon.
- **Honest engineering hygiene under hackathon time pressure**: 17 passing unit tests, a
  clean production build, SSRF guards on the one genuinely dangerous feature, graceful
  degradation on every external dependency, and a documented list of known limitations
  in the README rather than a claim of perfection.

---

## What we learned

Building an attacker taught us more about our defenses than building the defenses did.
Every heuristic feels solid until something systematically tries to walk around it — and
then the distinction between *hardenable* weaknesses (fix the matcher) and *fundamental*
ones (content alone cannot reveal a brand-free throwaway domain) becomes obvious and
actionable. That distinction is now the organizing principle of the entire product: the
header forensics, link tracing, and domain-intelligence layers all exist because the Lab
proved content analysis alone can be walked around.

We also learned how much credibility comes from stating limitations plainly. The README
has a "Known limitations" section listing exactly where the heuristics false-positive
and why. It made the project more convincing, not less.

---

## What's next for PhishLens

- **Finish the Python domain-intelligence layer** — WHOIS domain age, live SPF/DKIM/DMARC
  lookups, and a proper Unicode-confusables homoglyph table, so pasted (header-less)
  messages get the same domain scrutiny that uploaded `.eml` files do. The service
  contract and stub are in the repo; the detection logic is in progress.
- **A semantic evasion operator in the Red-Team Lab**, using an LLM to paraphrase rather
  than a substitution table — a strictly harder adversary to defend against.
- **Real inbox integration** (Gmail/Outlook add-in) so analysis happens where email
  already lives, instead of copy-paste.
- **Auto-hardening**: let the Lab propose matcher changes and show before/after detection
  rates across a corpus, closing the loop automatically.

---

## Built With

`typescript` · `next.js` · `react` · `tailwindcss` · `node.js` · `python` · `fastapi` ·
`anthropic-claude` · `postal-mime`

---

## Try it out / Installation

**Repository:** https://github.com/ivansts0110/phishlens-hackathon

Requires Node.js ≥20.9.

```bash
git clone https://github.com/ivansts0110/phishlens-hackathon
cd phishlens-hackathon
npm install
npm run dev
```

Open http://localhost:3000 — **go to `/lab` first** and click "Run adversarial
red-team" to see the core feature. No API keys required; every external integration is
optional. Run `npm test` for the test suite.

---

## Team

[[Your name — role]]
[[Teammate name — role, e.g. Python domain-intelligence service]]
