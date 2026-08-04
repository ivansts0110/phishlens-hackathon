# PhishLens Enrichment Service (Python)

A second signal source for PhishLens, separate from the TypeScript heuristic
engine in `../src/lib/phishing-engine.ts`. It answers questions that need
network calls (DNS, WHOIS) or are more naturally solved with Python's
ecosystem (scikit-learn) than with the synchronous, request-scoped rules
engine on the Node side.

## What it checks

All five checks run concurrently, each with its own timeout, under a total
budget of 3.2s — the Node caller gives up at 4s, and a single WHOIS lookup
can take three of those on its own.

| Check | Signal | Indicator |
|---|---|---|
| WHOIS creation date | Domain age in days | `domain-newly-registered` (28, <30d), `domain-recently-registered` (14, <180d) |
| SPF | TXT record present | `enrich-spf-missing` (15) |
| DMARC | `_dmarc` policy | `enrich-dmarc-absent` (12), `enrich-dmarc-none` (8) |
| DKIM | Common selector probe | none — reported in `meta` only, see below |
| Confusables | Look-alike domain | `enrich-confusable-domain` (18) |

**DKIM is deliberately not scored.** Probing common selectors
(`google`, `default`, `selector1`, …) can't find a key published under a
custom selector, and Google is exactly such a case — an early version docked
points from `google.com`. For a security tool, false-positiving the most
recognisable domain on the internet costs more trust than the signal is
worth, so `dkim_valid` is returned as context and never scored.

## Why this exists as a separate check

The Node engine already does two lightweight, dependency-free checks that
might look similar — worth understanding the difference:

- **Impersonation check** (`phishing-engine.ts`): string-matches a small
  hardcoded list of ~48 brand names/domains. Zero network calls, catches
  nothing outside that list.
- **Basic homograph check** (`mixedScriptOf` / `hasPunycodeLabel` in the same
  file): flags a domain if it visibly mixes Latin with Cyrillic/Greek
  characters, or is punycode-encoded.

The confusables check here is strictly stronger than that second one, in two
ways:

1. **Full Unicode confusables table** (via `confusable_homoglyphs`) rather
   than two hardcoded script ranges, so it catches substitutions the coarse
   check misses.
2. **Whole-script confusables**, which the library itself does not flag.
   `is_dangerous()` only detects *mixed*-script labels, so a domain written
   entirely in Cyrillic sails through it — including `xn--80ak6aa92e.com`,
   which renders as `аррӏе.com` and is the best-known homograph attack there
   is. `_is_whole_script_confusable` closes that gap: it maps every character
   to its ASCII look-alike and flags the label only if *all* of them map,
   meaning the label is a wholesale imitation of an ASCII word.

That second rule is what keeps legitimate non-Latin domains clean. `пример.рф`
contains Cyrillic characters with Latin look-alikes, but `п` has no ASCII
confusable at all, so the label doesn't fully map and isn't flagged. Verified
against a corpus of 7 attack domains and 18 legitimate ones, including
Cyrillic and Chinese IDNs, with no false positives either way.

Domain age and SPF/DMARC have no equivalent on the Node side at all. That's
genuinely new signal, not a rebuild of something that already exists.

## Contract

### `GET /health`
Returns `{"status": "ok"}`. Used for a liveness check before the Next.js
side bothers calling `/enrich`.

### `POST /enrich`

Request:
```json
{
  "sender_domain": "paypa1-support.com",
  "urls": ["http://paypa1-support.com/verify?id=8842"]
}
```
`sender_domain` may be an empty string if the message had no parseable
sender. `urls` may be an empty list.

Response:
```json
{
  "indicators": [
    {
      "id": "domain-recently-registered",
      "category": "sender",
      "label": "Recently registered domain",
      "detail": "paypa1-support.com was registered 4 days ago.",
      "weight": 25
    }
  ],
  "meta": {
    "sender_domain_age_days": 4,
    "spf_valid": false,
    "dkim_valid": null,
    "dmarc_policy": "none",
    "homoglyph_flag": false,
    "ml_phishing_probability": null
  }
}
```

`ml_phishing_probability` is reserved for a trained classifier and always
returns `null` today. It's part of the response shape so adding one later
doesn't break the contract; nothing consumes it yet.

**Rules for `indicators`:**
- `category` must be exactly one of `"sender" | "links" | "content" | "urgency"`
  — the Node side merges these directly into the same list the heuristic
  engine produces, and the frontend's category badge lookup will silently
  render nothing for anything else.
- `weight` is added straight into the 0–100 score alongside the TypeScript
  indicators. Look at the existing weights in `phishing-engine.ts` (20–35 for
  strong signals, 8–15 for weak ones) and size new indicators consistently —
  don't let a single Python indicator dominate the whole score.
- Return `"indicators": []` rather than omitting the field if nothing fired.

**Rules for `meta`:** all fields are optional / nullable. `null` means
"couldn't determine," not "checked and clean" — the two are different and
the frontend may eventually distinguish them, so don't collapse a failed
lookup into `false`.

**Never raise on a bad input or a failed lookup.** A DNS timeout, an invalid
domain, a WHOIS rate-limit — all of these should degrade to `None` for that
one field, not a 500. The Next.js caller already has its own timeout and
falls back to heuristic-only results if this whole service is unreachable,
but a request that *starts* successfully and then throws partway through is
worse than one that just returns partial data.

## Running it locally

```bash
cd python-service
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
uvicorn app:app --reload --port 8000
```

Then point the main app at it — in the repo root, add to `.env.local`:
```
PYTHON_SERVICE_URL=http://localhost:8000
```
Restart `npm run dev` and the analyzer will start calling `/enrich` for
every scan (see `src/lib/enrich.ts` in the main repo for the calling code —
it's the Node-side half of this contract and worth reading before you start,
since it shows exactly how your response gets consumed).

## Testing without the full app

```bash
curl -s -X POST http://localhost:8000/enrich \
  -H "content-type: application/json" \
  -d '{"sender_domain": "paypa1-support.com", "urls": ["http://paypa1-support.com/verify"]}' | python3 -m json.tool
```
