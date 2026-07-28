# Your task: PhishLens domain-intelligence service (Python)

## Context

PhishLens is our Cybersecurity-track hackathon project — it scores pasted
emails/messages for phishing risk in real time. The main app is a Next.js/
TypeScript rules engine (already built and working). Your part is a
**separate Python microservice** that adds signals the TypeScript side can't
easily get: WHOIS domain age, SPF/DKIM/DMARC DNS records, and (stretch goal)
a trained ML classifier. This is a real, load-bearing part of the project —
not a side quest — because it's the answer to the most likely judge question
in this track: *"how would this handle a phishing domain you don't already
know about?"* Right now the honest answer is "it mostly can't"; this service
is what fixes that.

Repo: `<your GitHub repo URL — fill in>`, everything you need is in
`python-service/`.

## What's already there

- `python-service/app.py` — a FastAPI skeleton with the full request/response
  contract already defined and working. Every check function is a stub that
  returns `None`. It runs today and the main app already calls it successfully
  — you're filling in real logic behind an interface that already works, not
  building the wiring from scratch.
- `python-service/README.md` — **read this first.** It's the technical contract:
  exact request/response JSON shape, which fields mean what, and the rules for
  never crashing on a bad lookup.
- `src/lib/enrich.ts` (in the main repo, not in `python-service/`) — the Node
  side that calls you. Worth skimming so you can see exactly how your response
  gets consumed, but you shouldn't need to change it.

## What to build

Four checks, roughly in priority order:

1. **Domain age via WHOIS** (`check_domain_age` in `app.py`). Newly-registered
   domains are one of the strongest phishing signals that exist — legitimate
   brands' domains are almost always years old. Use `python-whois`. Return
   days since registration, or `None` if the lookup fails/domain has no WHOIS
   record.

2. **SPF check** (`check_spf`). DNS TXT lookup on the domain for a
   `v=spf1 ...` record. Use `dnspython`. Return `True`/`False`/`None`
   (`None` = couldn't determine, not "no record" — see the contract doc for
   why that distinction matters).

3. **DMARC check** (`check_dmarc`). DNS TXT lookup at `_dmarc.<domain>`,
   parse out the `p=` policy value (`none` / `quarantine` / `reject`, or
   `absent` if there's no record at all). A domain with `p=none` or no DMARC
   record is weaker evidence than one with `p=reject`.

4. **Homoglyph check** (`check_homoglyphs`), a step up from what's already in
   TypeScript. The Node side does a *basic* mixed-Latin/Cyrillic/Greek check
   already (see "Why this exists as a separate check" in the README) — it
   misses subtler confusables. Use the `confusable_homoglyphs` package (or
   similar) for a real Unicode-confusables table instead of a hand-rolled
   script check.

5. **Stretch goal, only if time allows: `check_dkim` and/or an ML classifier**
   (`check_ml_classifier`). DKIM is selector-specific and genuinely hard to
   check generically from just a domain — don't sink time into it unless the
   other four are solid. The ML classifier (`scikit-learn`, TF-IDF + logistic
   regression on a small public phishing/legitimate URL dataset) is a nice
   demo moment ("we also trained a model") but is explicitly optional —
   ship without it if you're short on time.

Then wire your signals into the `indicators` list in the `enrich()` function
in `app.py` — there's a commented example showing the exact shape. Look at
the weights already used in `../src/lib/phishing-engine.ts` (20–35 for a
strong signal like impersonation, 8–15 for a weak one) and pick weights for
your indicators that are consistent with that scale — a domain registered
yesterday should probably weight similarly to the existing "raw IP address"
check (20), not overwhelm the whole score on its own.

## Ground rules (from the contract doc, repeating because they matter)

- **Never let a failed lookup raise.** Wrap each check's body in a
  try/except and return `None` on any failure — a WHOIS rate-limit or DNS
  timeout should never 500 the endpoint or hang the request.
- **`category` on every indicator must be exactly** `"sender"`, `"links"`,
  `"content"`, or `"urgency"` — nothing else, the frontend won't render
  anything else correctly.
- Keep response latency reasonable — the Node side times this call out at 4
  seconds total. WHOIS lookups in particular can be slow; don't do them
  serially if you end up checking multiple domains per request.

## How to run and test it standalone

```bash
cd python-service
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
uvicorn app:app --reload --port 8000
```

```bash
curl -s -X POST http://localhost:8000/enrich \
  -H "content-type: application/json" \
  -d '{"sender_domain": "paypa1-support.com", "urls": ["http://paypa1-support.com/verify"]}' \
  | python3 -m json.tool
```

Try it against a domain you know is old and legitimate (e.g.
`google.com`) and one that's freshly registered or doesn't exist, and
confirm the numbers make sense before wiring anything else.

## Testing against the full app

In the main repo root, add to `.env.local`:
```
PYTHON_SERVICE_URL=http://localhost:8000
```
Run `npm run dev` there, then `npm run dev`/`uvicorn` here at the same time,
and use the analyzer UI at `localhost:3000` normally — your indicators
should show up in the results panel alongside the TypeScript ones.

## Definition of done

- [ ] Domain age, SPF, and DMARC checks return real data, not `None`, for a
      few domains you've manually verified
- [ ] Each check fails closed (test this — kill your network mid-lookup or
      point at a garbage domain and confirm you get `None`, not a crash)
- [ ] At least one new `Indicator` shows up in the analyzer UI end-to-end for
      a domain your checks flag
- [ ] `python-service/README.md` updated if you changed the contract shape
      at all (try not to — the Node side depends on it as documented)

## Timeline

`<fill in your actual deadline here>` — ping me if the WHOIS/DNS parts are
taking longer than expected, that's the part most likely to have annoying
rate-limit/library quirks and I'd rather know early than at midnight before
submission.
