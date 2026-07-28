# PhishLens — handoff for the next session

## What this is
A Cybersecurity-track hackathon project (Next.js 16 / React 19 / TS / Tailwind v4,
Node ≥20.9). Repo: https://github.com/ivansts0110/phishlens-hackathon
Owner: ivansts0110. Design brief so far: **barebones on purpose** — plain
black/white/gray, square borders, system font, color only where functional
(risk level). Do NOT reintroduce gradients/glow/rounded pills unless the owner
asks for a design pass (that pass is explicitly deferred — "then we talk about design").

## Current state (all built, tested, pushed, working)
- `src/lib/phishing-engine.ts` — content scoring engine. `analyze(input, {hardened})`.
  `hardened:true` (default) Unicode-normalizes + strips zero-width chars before
  keyword matching; `hardened:false` is the naive baseline used by the Red-Team Lab.
- `src/lib/adversary.ts` + `/lab` + `/api/redteam` — **the headline feature**: the
  detector attacks itself, driving a phishing message 93→0 in five steps, then shows
  hardening recs and a hardened re-score (20, not 0). This is the demo money-shot.
- `.eml` upload + header forensics (`eml.ts`, `header-analysis.ts`), safe link tracer
  with SSRF guards (`trace.ts`, `/api/trace`), incident report (`/report/[id]`),
  webhook alerts (`alert.ts`, `ALERT_WEBHOOK_URL`), optional AI layer (`ai-explain.ts`,
  `ANTHROPIC_API_KEY`), optional Python enrichment stub (`python-service/`, teammate's
  task — see `python-service/ASSIGNMENT.md`), multi-tenant dashboard (`/dashboard`).
- **Accessibility pass done** (UX criterion explicitly names accessibility): global
  `:focus-visible` outline in `globals.css` (the per-field `outline-none` that hid
  keyboard focus is gone), skip-to-content link, `id="main"` landmarks on every page,
  keyboard-reachable `.eml` browse button (was a click-only div), `role="alert"` on
  errors, `aria-busy` on submit buttons, `scope="col"` on table headers, and the
  faintest text raised from /40–/50 to /60 opacity for WCAG-AA contrast. All verified
  in-browser with programmatic assertions.
- **`DEVPOST.md`** — paste-ready submission copy for every Devpost field. Only
  `[[double-bracketed]]` bits need filling (team names).
- **`DEMO_SCRIPT.md`** — shot-by-shot 2:45–3:00 video script with timings and exact
  narration, plus a 60-second cut.
- 17 unit tests (`npm test`), production build clean (`npm run build`).

## How to run / verify
- `npm install && npm run dev` → http://localhost:3000 (no keys needed).
- `npm test` for the engine/adversary/header unit tests.
- Browser verification pattern (used throughout): `npm install -D playwright`, write a
  tiny `verify.mjs` that drives chromium, asserts, and screenshots, run it, THEN
  `npm uninstall playwright` and delete `verify.mjs` before committing (keep it out of
  deps). Always `rm -rf data` (the runtime scan store, gitignored) before screenshots.
- Leave the dev server running when you finish a work session — the owner checks
  localhost and gets confused if it's been killed during cleanup.

## Guardrails learned the hard way
- Never leave a literal zero-width/invisible character in source; write `​`-style
  escapes (see how `ZERO_WIDTH` in phishing-engine.ts was fixed via a Python script).
- After a broad `git add`, review `git status`; keep `data/`, `.venv`, `.next`,
  `verify.mjs`, and `playwright` out of commits.
- Playwright locators match **DOM text, not CSS-transformed text** — `text=/START/`
  fails on markup that says `Start` styled with `uppercase`. Cost a false alarm once.
- Budget matters — the owner works in limited usage windows. Prove correctness with
  cheap deterministic unit tests first; reserve browser runs for one final pass that
  both asserts and screenshots.

## Judging criteria (weights) — optimize against these
Innovation 25% · Technical Excellence 25% · Real-World Impact 20% · UX & Design 15% ·
Presentation 15%. Teams are often multi-person; win on a novel core idea executed
cleanly, not volume. The Red-Team Lab is the Innovation play.

## Highest-value next moves (pick with the owner, don't assume)
1. **Record the demo video.** `DEMO_SCRIPT.md` is written and rehearsable; this is the
   single biggest remaining scoring gap and needs the owner's voice, not a model's.
2. **Fill in the team names in `DEVPOST.md` and submit.** Everything else in that file
   is accurate to the build — do not inflate the Python layer's status (it's a stub).
3. **Deploy a live URL.** Needs the owner's interactive login, so it wasn't done:
   ```bash
   npm i -g vercel && vercel login && vercel --prod
   ```
   Caveat to mention in the submission: the scan store is in-memory with best-effort
   disk persistence, so on serverless each instance keeps its own history. Fine for a
   demo; note it rather than hide it.
4. **Push the teammate's Python enrichment** to done (domain age / SPF-DKIM-DMARC /
   homoglyphs) so pasted (header-less) messages also get domain intelligence — the one
   place the product has a stub instead of a finished layer.
5. **Design pass** — deferred by the owner. When greenlit, elevate typography/spacing/
   hierarchy while staying restrained (security tool, not a toy). Load `impeccable`.
6. **Deepen the Red-Team Lab** for more Innovation/Technical weight: a semantic (LLM)
   evasion operator behind `ANTHROPIC_API_KEY`, or an "auto-harden" button showing
   before/after detection across a corpus.

## Confirm the event before more building
The owner said they found the specific hackathon; the deadline was never surfaced to
me and the public "Orion" Devpost I could find had already ended. Before large new
work, confirm with the owner that the target event is live and get the deadline.
