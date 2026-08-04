import asyncio
import time
from datetime import datetime, timezone
from functools import lru_cache
from typing import Literal, Optional
from urllib.parse import urlparse

import dns.resolver
import whois
from confusable_homoglyphs import confusables
from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI(title="PhishLens Enrichment Service")

DNS_TIMEOUT = 1.5
WHOIS_TIMEOUT = 2.5
TOTAL_BUDGET = 3.2
CACHE_TTL = 600

DKIM_SELECTORS = ["google", "default", "selector1", "selector2", "k1", "mail", "dkim", "s1", "s2"]

_cache: dict[str, tuple[float, "EnrichResponse"]] = {}


class EnrichRequest(BaseModel):
    sender_domain: str = ""
    urls: list[str] = []


class Indicator(BaseModel):
    id: str
    category: Literal["sender", "links", "content", "urgency"]
    label: str
    detail: str
    weight: int


class EnrichMeta(BaseModel):
    sender_domain_age_days: Optional[int] = None
    spf_valid: Optional[bool] = None
    dkim_valid: Optional[bool] = None
    dmarc_policy: Optional[str] = None
    homoglyph_flag: Optional[bool] = None
    ml_phishing_probability: Optional[float] = None


class EnrichResponse(BaseModel):
    indicators: list[Indicator] = []
    meta: EnrichMeta = EnrichMeta()


def _resolver() -> dns.resolver.Resolver:
    r = dns.resolver.Resolver()
    r.timeout = DNS_TIMEOUT
    r.lifetime = DNS_TIMEOUT
    return r


def _txt_records(name: str) -> list[str]:
    answers = _resolver().resolve(name, "TXT")
    out = []
    for rdata in answers:
        joined = "".join(part.decode("utf-8", "replace") for part in rdata.strings)
        out.append(joined)
    return out


def check_domain_age(domain: str) -> Optional[int]:
    if not domain:
        return None
    try:
        record = whois.whois(domain)
        created = record.creation_date
        if isinstance(created, list):
            created = next((c for c in created if c), None)
        if not isinstance(created, datetime):
            return None
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        delta = datetime.now(timezone.utc) - created
        return max(delta.days, 0)
    except Exception:
        return None


def check_spf(domain: str) -> Optional[bool]:
    if not domain:
        return None
    try:
        for record in _txt_records(domain):
            if record.lower().startswith("v=spf1"):
                return True
        return False
    except dns.resolver.NoAnswer:
        return False
    except Exception:
        return None


def check_dmarc(domain: str) -> Optional[str]:
    if not domain:
        return None
    try:
        for record in _txt_records(f"_dmarc.{domain}"):
            lowered = record.lower()
            if "v=dmarc1" not in lowered:
                continue
            for part in lowered.split(";"):
                part = part.strip()
                if part.startswith("p="):
                    policy = part[2:].strip()
                    if policy in {"none", "quarantine", "reject"}:
                        return policy
            return "none"
        return "absent"
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return "absent"
    except Exception:
        return None


def check_dkim(domain: str) -> Optional[bool]:
    if not domain:
        return None
    errors = 0
    for selector in DKIM_SELECTORS:
        try:
            for record in _txt_records(f"{selector}._domainkey.{domain}"):
                if "v=dkim1" in record.lower() or "p=" in record.lower():
                    return True
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            continue
        except Exception:
            errors += 1
    if errors == len(DKIM_SELECTORS):
        return None
    return False


@lru_cache(maxsize=4096)
def _latin_skeleton(char: str) -> Optional[str]:
    if char.isascii():
        return char
    try:
        found = confusables.is_confusable(char, preferred_aliases=["latin"])
    except Exception:
        return None
    if not found:
        return None
    for homoglyph in found[0].get("homoglyphs", []):
        candidate = homoglyph.get("c", "")
        if len(candidate) == 1 and candidate.isascii() and candidate.isalnum():
            return candidate
    return None


def _is_whole_script_confusable(label: str) -> bool:
    if len(label) < 3 or label.isascii():
        return False
    skeleton = []
    for char in label:
        mapped = _latin_skeleton(char)
        if mapped is None:
            return False
        skeleton.append(mapped)
    return "".join(skeleton) != label


def _label_is_confusable(label: str) -> bool:
    if not label:
        return False
    try:
        if confusables.is_dangerous(label):
            return True
    except Exception:
        pass
    return _is_whole_script_confusable(label)


def _hosts_from(domain: str, urls: list[str]) -> list[str]:
    hosts = [domain] if domain else []
    for url in urls:
        try:
            host = urlparse(url).hostname
            if host:
                hosts.append(host)
        except Exception:
            continue
    return hosts


def check_homoglyphs(domain: str, urls: list[str]) -> Optional[bool]:
    try:
        for host in _hosts_from(domain, urls):
            decoded = host
            if "xn--" in host:
                try:
                    decoded = host.encode("ascii").decode("idna")
                except Exception:
                    return True
            for label in decoded.split("."):
                if _label_is_confusable(label):
                    return True
        return False
    except Exception:
        return None


def check_ml_classifier(urls: list[str]) -> Optional[float]:
    return None


def build_indicators(meta: EnrichMeta, domain: str) -> list[Indicator]:
    indicators: list[Indicator] = []
    age = meta.sender_domain_age_days

    if age is not None and age < 30:
        indicators.append(Indicator(
            id="domain-newly-registered",
            category="sender",
            label="Newly registered sender domain",
            detail=f'"{domain}" was registered {age} day{"" if age == 1 else "s"} ago. '
                   "Phishing infrastructure is typically days or weeks old; established brands are years old.",
            weight=28,
        ))
    elif age is not None and age < 180:
        indicators.append(Indicator(
            id="domain-recently-registered",
            category="sender",
            label="Recently registered sender domain",
            detail=f'"{domain}" was registered {age} days ago, which is young for a domain sending business email.',
            weight=14,
        ))

    if meta.spf_valid is False:
        indicators.append(Indicator(
            id="enrich-spf-missing",
            category="sender",
            label="No SPF record published",
            detail=f'"{domain}" publishes no SPF record, so no server is formally authorized to send as it '
                   "and recipients cannot verify the sender.",
            weight=15,
        ))

    if meta.dmarc_policy == "absent":
        indicators.append(Indicator(
            id="enrich-dmarc-absent",
            category="sender",
            label="No DMARC policy published",
            detail=f'"{domain}" has no DMARC record, so spoofed mail claiming this domain is not rejected.',
            weight=12,
        ))
    elif meta.dmarc_policy == "none":
        indicators.append(Indicator(
            id="enrich-dmarc-none",
            category="sender",
            label="DMARC policy set to monitor only",
            detail=f'"{domain}" publishes DMARC with p=none, which reports abuse but does not block spoofing.',
            weight=8,
        ))

    if meta.homoglyph_flag:
        indicators.append(Indicator(
            id="enrich-confusable-domain",
            category="sender",
            label="Confusable characters in domain",
            detail="A domain in this message mixes character sets or uses non-Latin look-alikes that render "
                   "almost identically to a familiar brand.",
            weight=18,
        ))

    return indicators


async def gather_meta(domain: str, urls: list[str]) -> EnrichMeta:
    loop = asyncio.get_running_loop()

    async def run(fn, *args, timeout):
        try:
            return await asyncio.wait_for(loop.run_in_executor(None, fn, *args), timeout=timeout)
        except Exception:
            return None

    age, spf, dmarc, dkim, homoglyph = await asyncio.gather(
        run(check_domain_age, domain, timeout=WHOIS_TIMEOUT),
        run(check_spf, domain, timeout=DNS_TIMEOUT + 0.3),
        run(check_dmarc, domain, timeout=DNS_TIMEOUT + 0.3),
        run(check_dkim, domain, timeout=DNS_TIMEOUT + 0.7),
        run(check_homoglyphs, domain, urls, timeout=0.5),
    )

    return EnrichMeta(
        sender_domain_age_days=age,
        spf_valid=spf,
        dkim_valid=dkim,
        dmarc_policy=dmarc,
        homoglyph_flag=homoglyph,
        ml_phishing_probability=check_ml_classifier(urls),
    )


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/enrich", response_model=EnrichResponse)
async def enrich(req: EnrichRequest) -> EnrichResponse:
    domain = (req.sender_domain or "").strip().lower().strip(".")
    urls = req.urls[:20]

    key = f"{domain}|{','.join(sorted(urls))}"
    cached = _cache.get(key)
    if cached and time.time() - cached[0] < CACHE_TTL:
        return cached[1]

    try:
        meta = await asyncio.wait_for(gather_meta(domain, urls), timeout=TOTAL_BUDGET)
    except Exception:
        meta = EnrichMeta()

    response = EnrichResponse(indicators=build_indicators(meta, domain or "this domain"), meta=meta)

    _cache[key] = (time.time(), response)
    if len(_cache) > 500:
        for stale in [k for k, (ts, _) in _cache.items() if time.time() - ts > CACHE_TTL][:100]:
            _cache.pop(stale, None)

    return response
