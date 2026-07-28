# PhishLens — handoff for the next session

## What this is
A Cybersecurity-track hackathon project (Next.js 16 / React 19 / TS / Tailwind v4,
Node ≥20.9). Repo: https://github.com/ivansts0110/phishlens-hackathon
Owner: ivansts0110. Design brief so far: **barebones on purpose** — plain
black/white/gray, square borders, system font, color only where functional
(risk level). Do NOT reintroduce gradients/glow/rounded pills unless the owner
asks for a design pass (that pass is explicitly deferred).

## Current state (all built, tested, pushed, working)
- `src/lib/phishing-engine.ts` — content scoring engine. `analyze(input, {hardened})`.
  `hardened:true` (default) Unicode-normalizes + strips zero-width chars before
  keyword matching; `hardened:false` is the naive baseline used by the Red-Team Lab.
- `src/lib/adversary.ts` + `/lab` + `/api/redteam` — **the headline feature**: the
  detector attacks itself, driving a phishing message from Critical→Low step by step,
  then shows hardening recs and a hardened re-score. This is the demo money-shot.
- `.eml` upload + header forensics (`eml.ts`, `header-analysis.ts`), safe link tracer
  with SSRF guards (`trace.ts`, `/api/trace`), incident report (`/report/[id]`),
  webhook alerts (`alert.ts`, `ALERT_WEBHOOK_URL`), optional AI layer (`ai-explain.ts`,
  `ANTHROPIC_API_KEY`), optional Python enrichment stub (`python-service/`, teammate's
  task — see `python-service/ASSIGNMENT.md`), multi-tenant dashboard (`/dashboard`).
- 17 unit tests (`npm test`), production build clean (`npm run build`).

## How to run / verify
- `npm install && npm run dev` → http://localhost:3000 (no keys needed).
- `npm test` for the engine/adversary/header unit tests.
- Browser verification pattern (used throughout): `npm install -D playwright`, write a
  tiny `verify.mjs` that drives chromium and screenshots, run it, THEN
  `npm uninstall playwright` and delete `verify.mjs` before committing (keep it out of
  deps). Always `rm -rf data` (the runtime scan store, gitignored) before screenshots.
- Leave the dev server running when you finish a work session — the owner checks
  localhost and gets confused if it's been killed during cleanup.

## Guardrails learned the hard way
- Never leave a literal zero-width/invisible character in source; write `​` style
  escapes (see how `ZERO_WIDTH` in phishing-engine.ts was fixed via a Python script).
- After a broad `git add`, review `git status`; keep `data/`, `.venv`, `.next`,
  `verify.mjs`, and `playwright` out of commits.
- Budget matters — the owner works in limited usage windows. Prove correctness with
  cheap deterministic unit tests first; reserve browser runs for one final screenshot.

## Judging criteria (weights) — optimize against these
Innovation 25% · Technical Excellence 25% · Real-World Impact 20% · UX & Design 15% ·
Presentation 15%. Teams are often multi-person; win on a novel core idea executed
cleanly, not volume. The Red-Team Lab is the Innovation play.

## Highest-value next moves (pick with the owner, don't assume)
1. **Design pass (15%, currently intentionally bare).** The owner deferred this — when
   they greenlight it, elevate typography/spacing/hierarchy while keeping it
   professional and restrained (this is a security tool, not a toy). Load the
   `impeccable` skill.
2. **Presentation (15%): a 2–3 min demo video + Devpost writeup.** Script exists in
   README "Demo script" (lead with `/lab`). This is cheap points most teams fumble.
3. **Deploy a live URL** (currently local-only). Note: the in-memory store writes to
   disk best-effort and works read-only, but a serverless deploy won't persist history
   across instances — fine for a demo, mention it. Vercel is the fast path.
4. **Push the teammate's Python enrichment** to done (domain age / SPF-DKIM-DMARC /
   homoglyphs) so pasted (header-less) messages also get domain intelligence — this is
   the one place the product currently has a stub instead of a finished layer.
5. **Deepen the Red-Team Lab** if you want more Innovation/Technical weight: add a
   real semantic (LLM) evasion operator behind `ANTHROPIC_API_KEY`, or an
   "auto-harden" button that shows before/after detection on the whole corpus.

## Confirm the event before more building
The owner said they found the specific hackathon; the deadline was never surfaced to
me and the public "Orion" Devpost I could find had already ended. Before large new
work, confirm with the owner that the target event is live and get the deadline.
