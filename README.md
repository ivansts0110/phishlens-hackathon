# PhishLens

  Real-time phishing and social-engineering detection for email and messages.

  Built for the Cybersecurity track. I started PhishLens because phishing keeps getting better at looking ordinary, and a lot of security tools still feel either too heavy to demo or too vague to trust. The app takes a raw email or message, scores it in real time, and explains every point in plain English. It does that without ML training data or a third-party threat-intel subscription, and it also includes an optional AI
  summary, an optional Python domain-intelligence layer, and a multi-tenant dashboard for org-wide trends.

  Analyzer result view

  ## Why this exists

  Phishing is still one of the easiest ways into a real breach. Most tools on the market fall into one of two buckets. They are either big enterprise email-security suites that are expensive and hard to inspect, or they are keyword filters that miss basic evasion and never tell you why something was flagged.

  PhishLens is built around explainability. Every score is broken down into the indicators that triggered it, so a non-technical employee or a judge three minutes into a demo can see why a message looks dangerous.

  ## How it works

  1. Heuristic engine (src/lib/phishing-engine.ts, unit-tested in phishing-engine.test.ts) is a rules engine that scores a message against real phishing tradecraft:
      - Brand impersonation across ~48 commonly spoofed brands: the display name claims a brand but the domain does not match, the domain is a close typo, or the brand name is stuffed into an unrelated domain with no display-name claim at all
      - Homograph and lookalike-domain detection: punycode-encoded IDN domains, and domains where a single label mixes Latin with Cyrillic or Greek look-alike characters. The per-label check matters. Testing the whole hostname at once flags any non-Latin domain on a .com TLD, since com is itself Latin. This runs independently of the brand list, so it also catches impersonation of brands PhishLens does not know about. A
        label written entirely in one non-Latin script is invisible to this check by construction, and that case needs the full Unicode confusables table that is handled by the Python layer below.

      - Suspicious links: raw IP-address URLs, URL shorteners, abused top-level domains, and link text that does not match its actual destination
      - Urgency and threat language, credential and payment-harvesting phrasing, generic non-personalized greetings, Reply-To and sender domain mismatches, suspicious executable attachments

     Every trigger is a scored, human-readable indicator, not a black-box number.

  2. Adversarial Red-Team Lab (/lab, src/lib/adversary.ts, unit-tested in adversary.test.ts) is the headline feature. PhishLens attacks its own detector. Give it a message flagged as phishing and it plays the adversary, applying one evasion technique at a time, like invisible-character injection, urgency and threat paraphrasing, sender neutralization, and link laundering. It keeps whichever one lowers the risk score most,
     which creates a live step-by-step descent from Critical to Low. Every successful evasion becomes a concrete hardening recommendation, and the fully evaded message is re-scored against the hardened detector to show which attacks PhishLens already defeats, such as invisible-character injection after Unicode normalization, and which ones are fundamental limits of content-only analysis. That is the reason the header-
     forensics, link-tracing, and domain-intelligence layers exist. It is a defensive tool. It red-teams the classifier and outputs defenses. It does not manufacture novel phishing.

     Adversarial Red-Team Lab

  3. Raw email .eml header forensics (src/lib/eml.ts, src/lib/header-analysis.ts, unit-tested in header-analysis.test.ts) lets you drag a real .eml file onto the analyzer, where PhishLens parses the full message and reads forensic evidence that plain pasted text cannot carry:
      - The receiving mail server's own Authentication-Results, which include the SPF, DKIM, and DMARC verdicts computed at delivery time. A failing DKIM signature or SPF check is hard evidence of forgery, and the server's conclusion is used instead of re-doing DNS work.
      - Return-Path vs From and Reply-To vs From domain mismatches, which are staples of spoofing and invoice or executive-impersonation fraud
      - The Received: delivery-hop chain, surfaced in the report

  4. Safe link redirect tracer (src/lib/trace.ts, /api/trace) traces where any link in a message actually goes, hop by hop, server-side, without the user's browser ever touching the destination. Example chain: bit.ly/x -> tracker -> paypa1-support.com/login. Because fetching attacker-chosen URLs on the server is an SSRF risk by construction, every hop's hostname is resolved and blocked if it points at a private, loopback,
     or cloud-metadata address, with a cap on redirect count.

  5. Incident report and alerting (/report/[id], src/lib/alert.ts) gives every scan a clean, printable, PDF-able incident report with verdict, indicators, header forensics, delivery path, and links. If ALERT_WEBHOOK_URL is set, High and Critical scans fire a Slack-compatible webhook that also works with Discord and Mattermost. It is fire-and-forget and never blocks the scan.
  6. Optional AI layer (src/lib/ai-explain.ts) asks Claude to turn the indicator list into a 3 to 5 sentence plain-English explanation and recommended action for a non-technical recipient if ANTHROPIC_API_KEY is set. It is bounded by an 8 second timeout. If it is slow, errors, or the key is missing, the app falls back to heuristic-only results and says so in the UI instead of silently doing nothing.
  7. Optional Python enrichment layer (python-service/) is a FastAPI service that provides a second signal source for things that need a live network call, which is exactly what a pasted message with no headers is missing: WHOIS domain age, SPF and DMARC record lookups, and full-table Unicode confusables detection. All checks run concurrently, each with its own timeout, under a 3.2 second budget. The Node caller gives up
     at 4 seconds, and a single WHOIS query can take three of them. Every check fails closed to null ("couldn't determine"), never an exception.

     The confusables check is stronger than the Node-side one in a specific way worth knowing. Standard mixed-script detection misses domains written entirely in a non-Latin script, so xn--80ak6aa92e.com, which renders as аррӏе.com, the best-known homograph attack there is, passes it. This layer maps each character to its ASCII look-alike and flags the label only when all of them map, catching whole-script imitation while
     leaving genuine non-Latin domains (пример.рф, 中国.cn) alone.

     DKIM is checked but deliberately not scored. Probing common selectors cannot see a key published under a custom one, and an early version docked points from google.com because of it. It is returned as context instead. The same optional-dependency pattern as the AI layer applies here. If PYTHON_SERVICE_URL is unset or the service is down or slow, the app degrades gracefully and never hard-fails. See python-service/
     README.md.

  8. Multi-tenant scan history (src/lib/store.ts) tags every scan with an organization and stores it, which powers the /dashboard view with total scans, average risk score, risk distribution, and a searchable history table.

  Dashboard view

  ## Installation

  Requires Node.js >=20.9. That is the Next.js 16 minimum.

  npm install
  npm run dev

  Open http://localhost:3000 (http://localhost:3000). The heuristic engine needs no API keys or external services.

  Run the test suite:

  npm test

  To enable the optional AI explanation layer, copy .env.example to .env.local and add an Anthropic API key:

  cp .env.example .env.local
  # then edit .env.local and set ANTHROPIC_API_KEY

  To enable the optional Python enrichment layer, see python-service/README.md, then set PYTHON_SERVICE_URL in .env.local, for example http://localhost:8000.

  To enable High and Critical webhook alerts, set ALERT_WEBHOOK_URL in .env.local to a Slack, Discord, or Mattermost incoming-webhook URL.

  ## Demo script

  1. Open the money shot first by going to /lab and click Run adversarial red-team. Watch PhishLens attack its own detector and drive a Critical 93 phishing email down to Low 0 step by step, then read the hardening report showing which evasion it already defeats and why the rest of the product's layers exist. This is the moment where people sit up.
  2. Go to / and click a sample button to load a realistic message, or paste your own. Then click Analyze message and watch the score, indicator list, and, if a key is set, the AI summary populate.
  3. Drag docs/samples/phishing-sample.eml onto the dropzone and analyze it. That adds the header-forensics panel, including failing SPF, DKIM, and DMARC plus Return-Path and Reply-To mismatches, on top of the content indicators and pushes it to a 100 Critical verdict.
  4. In the Extracted links panel, click Trace destination on the link to follow its redirect chain server-side to the real endpoint.
  5. Click View full incident report for the printable and PDF-able summary.
  6. Go to /dashboard for the org-wide scan history and risk distribution.
  7. If ALERT_WEBHOOK_URL is set to a Slack channel, analyze the .eml sample live and watch the red alert land in Slack mid-demo.

  ## Project structure

  src/
    app/
      page.tsx                 analyzer UI (home)
      dashboard/page.tsx       org-scoped scan history and stats
      report/[id]/page.tsx     printable incident report for a scan
      api/analyze/route.ts     POST: scores a message/.eml, stores it, returns result
      api/history/route.ts     GET: scan history and known orgs
      api/trace/route.ts       POST: safely trace a link's redirect chain
    components/
      AnalyzerForm.tsx         form, .eml dropzone, results, link tracer (client)
      RiskGauge.tsx            score and level display
      Nav.tsx / PrintButton.tsx shared nav bar / print control
    lib/
      phishing-engine.ts       content scoring engine (pure functions, unit-tested)
      header-analysis.ts       .eml header forensics (unit-tested)
      eml.ts                   raw .eml parsing (postal-mime)
      trace.ts                 link redirect tracer with SSRF guards
      alert.ts                 High/Critical webhook alerts
      ai-explain.ts            optional Claude API call, with timeout and status
      enrich.ts                optional Python service call, with timeout and status
      rate-limit.ts            in-memory per-IP rate limiter for the API routes
      store.ts                 in-memory scan history, best-effort disk persistence
      samples.ts               canned demo messages
  docs/samples/phishing-sample.eml  demo email with failing auth and spoofed headers
  python-service/
    app.py                    FastAPI enrichment: WHOIS age, SPF/DMARC, confusables
    requirements.txt

  ## Known limitations

  Being upfront about these rather than papering over them:

  - Keyword heuristics can false-positive on legitimate marketing email. A real "Sale ends today!" newsletter can trip the urgency-language indicator. Weights are tuned so a single such indicator stays in the Low band, but an aggressive marketing email combined with a generic greeting could tip into Medium.
  - Link-text-mismatch detection only works on markdown or HTML-style links ([text](url) or <a href>), not plain "click here: http://evil.com" text. Pasting plain text has no way to represent a styled hyperlink. Uploading the original .eml preserves the real HTML anchors, so this is much stronger on uploaded emails.
  - Header forensics requires the raw .eml. A copy-pasted message body has no headers, so SPF, DKIM, DMARC, and Return-Path analysis only run on uploaded files. That is inherent because the evidence is not present in pasted text.
  - The brand-impersonation list is finite at roughly 48 well-known brands. Impersonation of anything outside it relies on the homograph and typo checks catching it, or on the Python enrichment layer's domain-intelligence signals, which are brand-agnostic.
  - The Python layer's DKIM check is informational, not scored because selector probing produces false negatives on domains using custom selectors. A real deployment would read the DKIM result from the receiving server's Authentication-Results header instead, which PhishLens already does for uploaded .eml files.
  - WHOIS coverage is uneven across TLDs. Some registries rate-limit or withhold creation dates. In that case domain age returns "couldn't determine" rather than a wrong answer, so the absence of an age indicator is not evidence that a domain is old.
  - The in-memory store is single-process. It survives concurrent requests within one running server with no read-modify-write race, and it persists to disk best-effort for local dev convenience. On a multi-instance serverless deploy, each instance would have its own history. That is fine for a hackathon demo, and a real deployment would swap this for a shared database.
  - The in-memory rate limiter is per-instance, not distributed. It stops casual single-source abuse of a public demo URL, but it is not a substitute for a real rate limiter such as Upstash or Redis in production.

  ## Roadmap

  - Real inbox integration, like a Gmail or Outlook add-in, instead of copy-paste and file upload
  - Persistent shared database plus auth instead of a local JSON store
  - A trained phishing classifier in the Python layer, with ml_phishing_probability already in the response contract and currently always null
  - Attachment content scanning, not just filename heuristics

  ## Team

  Ivan S. (https://linkedin.com/in/ivan-stashchak)
