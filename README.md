# PhishLens

**Real-time phishing & social-engineering detection for email and messages.**

Built for the Cybersecurity track. PhishLens takes a raw email or message (sender,
subject, body) and returns an explainable risk score in real time — no ML training
data or third-party threat-intel subscription required — plus an optional
AI-generated plain-English summary, an optional Python domain-intelligence layer,
and a multi-tenant dashboard so a security team can see trends across an
organization.

![Analyzer result view](docs/screenshots/analyzer-result.png)

## Why this exists

Phishing remains the single most common entry point for breaches, and most existing
tools are either heavyweight enterprise email-security suites (expensive, opaque) or
naive keyword blockers (easy to evade, no explanation of *why* something was flagged).
PhishLens focuses on **explainability**: every score is broken down into the specific
indicators that triggered it, so a non-technical employee — or a judge three minutes
into a demo — can see exactly why a message is dangerous.

## How it works

1. **Heuristic engine** (`src/lib/phishing-engine.ts`, unit-tested in
   `phishing-engine.test.ts`) — a rules engine that scores a message against real
   phishing tradecraft:
   - Brand impersonation across ~48 commonly-spoofed brands: display name claims a
     brand but the domain doesn't match, the domain is a close typo, *or* the brand
     name is simply stuffed into an unrelated domain with no display-name claim at all
   - Homograph / lookalike-domain detection: mixed-script domains (Latin mixed with
     Cyrillic/Greek look-alike characters) and punycode-encoded (IDN) domains — this
     runs independently of the brand list, so it also catches impersonation of brands
     PhishLens doesn't know about
   - Suspicious links: raw IP-address URLs, URL shorteners, abused top-level domains,
     and link text that doesn't match its actual destination
   - Urgency and threat language, credential/payment-harvesting phrasing, generic
     non-personalized greetings, Reply-To/sender domain mismatches, suspicious
     executable attachments

   Every trigger is a scored, human-readable indicator, not a black-box number.

2. **Optional AI layer** (`src/lib/ai-explain.ts`) — if `ANTHROPIC_API_KEY` is set,
   the app asks Claude to turn the indicator list into a 3–5 sentence plain-English
   explanation and recommended action for a non-technical recipient. Bounded by an
   8s timeout; if it's slow, errors, or the key isn't set, the app falls back to
   heuristic-only results and says so in the UI rather than silently doing nothing.

3. **Optional Python enrichment layer** (`python-service/`) — a second signal source
   for things that need a network call (WHOIS domain age, SPF/DKIM/DMARC records) or
   are more naturally solved in Python (a trained phishing classifier). Same
   optional-dependency pattern as the AI layer: unset `PYTHON_SERVICE_URL` or a
   down/slow service degrades to heuristic-only, never a hard failure. **This part is
   a contract + stub, not a finished feature** — see `python-service/README.md`.

4. **Multi-tenant scan history** (`src/lib/store.ts`) — every scan is tagged with an
   organization and stored, powering the `/dashboard` view: total scans, average risk
   score, risk distribution, and a searchable history table.

![Dashboard view](docs/screenshots/dashboard.png)

## Installation

Requires **Node.js ≥20.9** (Next.js 16's minimum).

```bash
npm install
npm run dev
```

Open [http://localhost:3000](http://localhost:3000). That's it — the heuristic engine
needs no API keys or external services.

Run the test suite:

```bash
npm test
```

To enable the optional AI explanation layer, copy `.env.example` to `.env.local` and
add an Anthropic API key:

```bash
cp .env.example .env.local
# then edit .env.local and set ANTHROPIC_API_KEY
```

To enable the optional Python enrichment layer, see `python-service/README.md`, then
set `PYTHON_SERVICE_URL` (e.g. `http://localhost:8000`) in `.env.local`.

## Demo script

1. Go to `/` and click one of the sample buttons (**Fake PayPal account alert**,
   **DocuSign urgent signature request**, or **Legitimate internal email**) to
   instantly load a realistic message.
2. Click **Analyze message** — watch the risk gauge, indicator list, and (if an API
   key is set) the AI summary populate.
3. Go to `/dashboard` to see the scan logged against its organization, alongside
   aggregate stats and risk distribution across all scans so far.
4. Paste in your own suspicious email to show it isn't just hard-coded to the samples.

## Project structure

```
src/
  app/
    page.tsx                analyzer UI (home)
    dashboard/page.tsx       org-scoped scan history + stats
    api/analyze/route.ts     POST: scores a message, stores it, returns result
    api/history/route.ts     GET: scan history + known orgs
  components/
    AnalyzerForm.tsx          form + results panel (client component)
    RiskGauge.tsx              circular score gauge
    Nav.tsx                    shared nav bar
  lib/
    phishing-engine.ts         scoring engine (pure functions, unit-tested)
    phishing-engine.test.ts    unit tests (node:test via tsx)
    ai-explain.ts               optional Claude API call, with timeout + status
    enrich.ts                   optional Python service call, with timeout + status
    rate-limit.ts                in-memory per-IP rate limiter for the API routes
    store.ts                     in-memory scan history, best-effort disk persistence
    samples.ts                   canned demo messages
python-service/
  app.py                        FastAPI contract + stub (see its own README)
  requirements.txt
```

## Known limitations

Being upfront about these rather than papering over them:

- **Keyword heuristics can false-positive on legitimate marketing email.** A real
  "Sale ends today!" newsletter can trip the urgency-language indicator. Weights are
  tuned so a single such indicator alone stays in the Low band, but an aggressive
  marketing email combined with a generic greeting could tip into Medium.
- **Link-text-mismatch detection only works on markdown/HTML-style links**
  (`[text](url)` or `<a href>`), not plain "click here: http://evil.com" text, since
  the input is a plain-text paste with no way to represent a styled hyperlink where
  the visible text differs from the destination.
- **The brand-impersonation list is finite** (~48 well-known brands). Impersonation of
  anything outside it relies on the homograph/typo checks catching it, or on the
  Python enrichment layer's domain-intelligence signals (domain age, SPF/DKIM/DMARC)
  once those are built.
- **The in-memory store is single-process.** It survives concurrent requests within
  one running server (no read-modify-write race), and persists to disk best-effort
  for local dev convenience, but on a multi-instance serverless deploy each instance
  would have its own history. Fine for a hackathon demo; a real deployment would swap
  this for a shared database.
- **The in-memory rate limiter is per-instance**, not distributed. It stops casual
  single-source abuse of a public demo URL; it isn't a substitute for a real
  rate limiter (e.g. Upstash/Redis) in production.

## Roadmap (beyond the hackathon scope)

- Real inbox integration (Gmail/Outlook add-in) instead of copy-paste
- Persistent shared database + auth instead of a local JSON store
- Finish the Python enrichment layer (see `python-service/README.md`)
- Attachment content scanning, not just filename heuristics
- Org-level alerting/Slack webhook when a Critical-risk message is scanned

## Team

_Add your team members' names and roles here before submitting._
