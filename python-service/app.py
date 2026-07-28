"""
PhishLens domain-intelligence enrichment service — STUB.

This service is intentionally unimplemented. It defines the contract the
Next.js app already calls (see src/lib/enrich.ts in the main repo) and
returns safe placeholder responses so the rest of the app keeps working
end-to-end while the real detection logic is built.

See README.md in this directory for the full task brief.

Run it with:
    pip install -r requirements.txt
    uvicorn app:app --reload --port 8000
"""

from typing import Literal, Optional

from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI(title="PhishLens Enrichment Service")


class EnrichRequest(BaseModel):
    sender_domain: str = ""
    urls: list[str] = []


class Indicator(BaseModel):
    id: str
    # Must be one of these four to match the TypeScript Indicator type in
    # src/lib/phishing-engine.ts — the Next.js side merges these in directly.
    category: Literal["sender", "links", "content", "urgency"]
    label: str
    detail: str
    weight: int


class EnrichMeta(BaseModel):
    sender_domain_age_days: Optional[int] = None
    spf_valid: Optional[bool] = None
    dkim_valid: Optional[bool] = None
    dmarc_policy: Optional[str] = None  # "none" | "quarantine" | "reject" | "absent"
    homoglyph_flag: Optional[bool] = None
    ml_phishing_probability: Optional[float] = None  # stretch goal, omit if not built


class EnrichResponse(BaseModel):
    indicators: list[Indicator] = []
    meta: EnrichMeta = EnrichMeta()


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/enrich", response_model=EnrichResponse)
def enrich(req: EnrichRequest) -> EnrichResponse:
    # TODO(teammate): replace each stub call below with a real implementation.
    # Every check must fail closed — catch its own exceptions and return None/
    # empty rather than raising, so one broken DNS/WHOIS lookup never 500s the
    # whole request. The Next.js caller already has its own timeout + fallback,
    # but this service should never be the thing that crashes a demo.

    domain_age_days = check_domain_age(req.sender_domain)
    spf_valid = check_spf(req.sender_domain)
    dkim_valid = check_dkim(req.sender_domain)
    dmarc_policy = check_dmarc(req.sender_domain)
    homoglyph_flag = check_homoglyphs(req.sender_domain, req.urls)
    ml_probability = check_ml_classifier(req.urls)  # stretch goal, may stay None

    indicators: list[Indicator] = []

    # TODO(teammate): turn the raw signals above into Indicator entries, e.g.:
    # if domain_age_days is not None and domain_age_days < 30:
    #     indicators.append(Indicator(
    #         id="domain-recently-registered",
    #         category="sender",
    #         label="Recently registered domain",
    #         detail=f"{req.sender_domain} was registered {domain_age_days} days ago.",
    #         weight=25,
    #     ))

    return EnrichResponse(
        indicators=indicators,
        meta=EnrichMeta(
            sender_domain_age_days=domain_age_days,
            spf_valid=spf_valid,
            dkim_valid=dkim_valid,
            dmarc_policy=dmarc_policy,
            homoglyph_flag=homoglyph_flag,
            ml_phishing_probability=ml_probability,
        ),
    )


def check_domain_age(domain: str) -> Optional[int]:
    # TODO(teammate): WHOIS lookup (python-whois) -> days since registration.
    return None


def check_spf(domain: str) -> Optional[bool]:
    # TODO(teammate): DNS TXT lookup for "v=spf1 ..." (dnspython).
    return None


def check_dkim(domain: str) -> Optional[bool]:
    # TODO(teammate): DKIM is selector-specific and can't always be checked
    # from the domain alone — see README for how to scope this reasonably.
    return None


def check_dmarc(domain: str) -> Optional[str]:
    # TODO(teammate): DNS TXT lookup at _dmarc.<domain> -> parse p= policy.
    return None


def check_homoglyphs(domain: str, urls: list[str]) -> Optional[bool]:
    # TODO(teammate): confusable-character detection beyond the basic
    # mixed-script check already done in TypeScript (see README "Why this
    # exists as a separate check" section).
    return None


def check_ml_classifier(urls: list[str]) -> Optional[float]:
    # TODO(teammate, stretch goal): TF-IDF + logistic regression or similar,
    # trained on a small public phishing/legitimate URL dataset.
    return None
