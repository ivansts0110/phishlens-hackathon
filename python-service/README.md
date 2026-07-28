# PhishLens Enrichment Service (Python)

A second signal source for PhishLens, separate from the TypeScript heuristic
engine in `../src/lib/phishing-engine.ts`. It answers questions that need
network calls (DNS, WHOIS) or are more naturally solved with Python's
ecosystem (scikit-learn) than with the synchronous, request-scoped rules
engine on the Node side.

**Current state: contract + stub only.** `app.py` defines the API shape and
returns empty/placeholder data so the rest of the app runs end-to-end today.
The actual detection logic is unimplemented — that's the assignment. See the
handoff brief for full context; this file is the technical reference to work
against while building.

## Why this exists as a separate check

The Node engine already does two lightweight, dependency-free checks that
might look similar to what's asked here — worth understanding the difference
so effort isn't duplicated:

- **Impersonation check** (`phishing-engine.ts`): string-matches a small
  hardcoded list of ~48 brand names/domains. Zero network calls, catches
  nothing outside that list.
- **Basic homograph check** (`mixedScriptOf` / `hasPunycodeLabel` in the same
  file): flags a domain if it visibly mixes Latin with Cyrillic/Greek
  characters, or is punycode-encoded. This is a coarse, single-pass string
  check — it doesn't use a real confusable-character table, so it misses
  subtler substitutions (e.g. Cyrillic "е" that renders identically to Latin
  "e" but isn't in the two script ranges checked). Prefer a proper library
  (e.g. `confusable_homoglyphs`) here.

Everything else below — domain age, SPF/DKIM/DMARC, a trained classifier —
has no equivalent on the Node side at all. That's genuinely new signal, not
a rebuild of something that already exists.

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
    "ml_phishing_probability": 0.94
  }
}
```

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
