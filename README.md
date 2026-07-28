# PhishLens

**Real-time phishing & social-engineering detection for email and messages.**

Built for the Cybersecurity track. PhishLens takes a raw email or message (sender,
subject, body) and returns an explainable risk score in real time — no ML training
data or third-party threat-intel subscription required — plus an optional
AI-generated plain-English summary, and a multi-tenant dashboard so a security team
can see trends across an organization.

## Why this exists

Phishing remains the single most common entry point for breaches, and most existing
tools are either heavyweight enterprise email-security suites (expensive, opaque) or
naive keyword blockers (easy to evade, no explanation of *why* something was flagged).
PhishLens focuses on **explainability**: every score is broken down into the specific
indicators that triggered it, so a non-technical employee — or a judge three minutes
into a demo — can see exactly why a message is dangerous.

## How it works

1. **Heuristic engine** (`src/lib/phishing-engine.ts`) — a rules engine that scores a
   message against real phishing tradecraft:
   - Brand impersonation (display name claims a known brand like PayPal/DocuSign/
     Microsoft, but the sending domain doesn't match — including both close typo
     domains and brand-name-stuffed unrelated domains)
   - Suspicious links: raw IP-address URLs, URL shorteners, abused top-level domains,
     and link text that doesn't match its actual destination
   - Urgency and threat language ("act now", "account will be locked")
   - Credential/payment-harvesting phrasing
   - Generic, non-personalized greetings
   - Reply-To/sender domain mismatches and suspicious executable attachments

   Every trigger is a scored, human-readable indicator, not a black-box number.

2. **Optional AI layer** (`src/lib/ai-explain.ts`) — if `ANTHROPIC_API_KEY` is set,
   the app also asks Claude to turn the indicator list into a 3–5 sentence plain-
   English explanation and recommended action for a non-technical recipient. The app
   is fully functional without this key; it's an enhancement, not a dependency.

3. **Multi-tenant scan history** (`src/lib/store.ts`) — every scan is tagged with an
   organization and stored, powering the `/dashboard` view: total scans, average risk
   score, risk distribution, and a searchable history table. This is the seed of the
   "enterprise security tool" story — the same engine could sit behind a mail
   gateway or Slack/Teams bot and aggregate risk across a whole company.

## Installation

Requires Node.js 18+.

```bash
npm install
npm run dev
```

Open [http://localhost:3000](http://localhost:3000). That's it — the heuristic engine
needs no API keys or external services.

To enable the optional AI explanation layer, copy `.env.example` to `.env.local` and
add an Anthropic API key:

```bash
cp .env.example .env.local
# then edit .env.local and set ANTHROPIC_API_KEY
```

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
    page.tsx              analyzer UI (home)
    dashboard/page.tsx     org-scoped scan history + stats
    api/analyze/route.ts   POST: scores a message, stores it, returns result
    api/history/route.ts   GET: scan history + known orgs
  components/
    AnalyzerForm.tsx        form + results panel (client component)
    RiskGauge.tsx            circular score gauge
    Nav.tsx                  shared nav bar
  lib/
    phishing-engine.ts       scoring engine (pure functions, unit-testable)
    ai-explain.ts             optional Claude API call
    store.ts                  JSON-file-backed scan history
    samples.ts                canned demo messages
```

## Roadmap (beyond the hackathon scope)

- Real inbox integration (Gmail/Outlook add-in) instead of copy-paste
- Persistent database + auth instead of a local JSON file
- Attachment content scanning, not just filename heuristics
- Org-level alerting/Slack webhook when a Critical-risk message is scanned

## Team

_Add your team members' names and roles here before submitting._
