# PhishLens — demo video script (target: 2:45–3:00)

Judged on "quality of demonstration, storytelling, documentation, and ability to
communicate the solution." The structure below front-loads the differentiator: most
submissions open by explaining their problem space for 45 seconds. **We open with the
thing nobody else has**, then justify it.

## Before you hit record

```bash
cd phishlens-hackathon
rm -rf data          # clears seeded scan history so the dashboard looks fresh
npm run dev
```

- Browser at **1280px wide**, zoom 100%, no bookmarks bar, no extensions visible.
- Have three tabs pre-opened: `/lab`, `/`, `/dashboard`.
- Have `docs/samples/phishing-sample.eml` visible in a Finder window for the drag.
- Do one full silent rehearsal — the red-team run takes ~1s, don't get caught waiting.
- Record at 1080p. Speak at a normal pace; do not rush the Lab section.

---

## [0:00–0:20] — Cold open on the Lab

**Screen:** `/lab`, already loaded, phishing sample pre-filled.

> "This is a phishing email. Our detector rates it 93 out of 100 — Critical.
> Now watch what happens when the detector attacks itself."

**Action:** Click **Run adversarial red-team**. Let the result render. Pause a beat.

> "Ninety-three to zero. Five steps."

*Don't explain yet. Let the number land.*

---

## [0:20–1:05] — What just happened

**Screen:** Scroll slowly through the step cards.

> "PhishLens just played the attacker against its own classifier. Each step applies one
> real evasion technique and keeps whichever one lowers the score most.
>
> Step one — it strips the impersonated brand from the sender. Ninety-three to fifty-eight.
>
> Step two is my favourite: it injects invisible zero-width Unicode characters inside
> 'verify your password'. To a human the text is identical. To a naive keyword matcher,
> that phrase no longer exists. Fifty-eight to thirty-eight.
>
> Then it paraphrases the urgency, paraphrases the threat, launders the link — and the
> email is invisible."

**Action:** Scroll to the **Hardening report**.

> "But here's the part that matters. Every evasion becomes a recommendation — and
> PhishLens re-scores the fully-evaded email against its *hardened* self. The
> invisible-character attack is already dead: that same email scores 20, not 0, because
> building this feature is what made us add Unicode normalization to the matcher.
>
> The attacks that survive aren't bugs. They're the fundamental limit of reading message
> content — and they're the reason for everything I'm about to show you."

---

## [1:05–1:50] — The layers the Lab justifies

**Screen:** Switch to `/`. Drag `phishing-sample.eml` onto the dropzone.

> "Content analysis can be walked around. So PhishLens doesn't only read content.
> This is a real email file."

**Action:** Click **Analyze message**. Let the header-forensics panel render.

> "Now we're reading the headers. SPF: fail. DKIM: fail. DMARC: fail — that's the
> receiving mail server's own cryptographic verdict, not our guess. The Return-Path and
> Reply-To both point somewhere different from the visible sender. Eleven indicators,
> 100 out of 100. You cannot paraphrase your way out of a failed DKIM signature."

**Action:** Scroll to **Extracted links**, click **Trace destination**.

> "And links get traced server-side — we follow the redirect chain to the real
> destination so the user's browser never touches it. That tracer refuses to resolve
> private or cloud-metadata addresses, because a link tracer is an SSRF vulnerability if
> you build it carelessly."

---

## [1:50–2:20] — Operational reality

**Action:** Click **View full incident report**.

> "Every scan produces a printable incident report — verdict, indicators, header
> forensics, the full delivery path with the real sending IP."

**Action:** Switch to `/dashboard`.

> "And it aggregates per organization: scan history, risk distribution, most common
> attack indicator. High and Critical scans fire a Slack webhook, so a security team
> sees this where they already work."

*(If you've wired a real Slack webhook: show the alert landing. Strong beat — but only
if it's reliable. Cut it rather than risk a dead demo.)*

---

## [2:20–2:50] — Close on the thesis

**Screen:** Back to `/lab`, hardening report visible.

> "Most detection tools ask you to trust a score. PhishLens shows you exactly where its
> score breaks, tells you what to layer on top, and proves which attacks it's already
> fixed.
>
> Seventeen unit tests, no API keys required to run it, every external service optional
> and failing soft. Clone it and the whole thing works in two commands.
>
> A detector that hasn't been red-teamed is a detector you don't understand. So we
> red-teamed ours — and then we fixed it."

**End card:** repo URL, 3 seconds.

---

## Things that will cost you points if you skip them

- **Do not narrate the code.** No file tours, no IDE. Judges score the *solution*.
- **Do not apologize** for the plain interface. Frame it once, early, only if it comes
  up: "we kept the interface deliberately quiet so the engineering carries it."
- **Do not claim the Python enrichment layer is finished** — it's a contract and a stub.
  If it comes up: "the service contract's defined and wired in, detection logic is in
  progress." Judges check repos; an overclaim is worse than a gap.
- **Show, then explain.** Every section above leads with the action and follows with the
  sentence. Reversing that order is what makes demos boring.

## If you only have 60 seconds

Cut to: the Lab run (0:00–0:20), the hardening report line (0:45–1:05), the `.eml` drop
with SPF/DKIM/DMARC failing (1:05–1:30), and the closing two sentences. That's the whole
argument.
