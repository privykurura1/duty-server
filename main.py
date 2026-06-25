# main.py
# Fambai CV — Job Scan (pure logic, no AI/API key required)
# v2: adds URL/company verification — detects domain impersonation, typosquatting,
# suspicious TLDs, and newly-registered domains, on top of the existing
# scam-phrase rules engine.
#
# Run locally:
#   pip install -r requirements.txt
#   uvicorn main:app --reload --host 0.0.0.0 --port 8000
#
# Test:
#   Open http://localhost:8000/docs
#
# Deploy (Render.com):
#   Start command -> uvicorn main:app --host 0.0.0.0 --port $PORT

import difflib
import json
import re
from datetime import datetime
from typing import List, Optional, Tuple
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup
from fastapi import FastAPI
from pydantic import BaseModel

# WHOIS is optional — if the package isn't installed or the lookup fails
# (some registries block/rate-limit it), domain-age checking is just skipped
# rather than crashing the request.
try:
    import whois as whois_lib
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False

app = FastAPI(title="Fambai CV — Job Scan")

URL_PATTERN = re.compile(r"^https?://\S+$", re.IGNORECASE)


# ---------- Request / Response models ----------

class JobScanRequest(BaseModel):
    input: str  # either a URL or pasted job ad text


class JobScanResponse(BaseModel):
    score: int
    label: str
    warnings: List[str]
    source_type: str  # "url" or "text"
    fetch_failed: bool = False
    domain: Optional[str] = None
    detected_company: Optional[str] = None
    confidence: str = "medium"  # "low" / "medium" / "high" — how much signal we had to work with
    disclaimer: str = (
        "This is an automated check based on common scam patterns. It can miss real "
        "scams and can occasionally flag a genuine job ad incorrectly. Always verify "
        "independently and never pay money to apply for, secure, or start a job."
    )


# ---------- Fetching ----------

def fetch_page(url: str) -> Optional[Tuple[BeautifulSoup, str, int]]:
    """Best-effort fetch of a job posting URL. Follows redirects (so
    shortened links like bit.ly/tinyurl resolve to their real destination)
    and returns (soup, final_url, redirect_count), or None on failure
    (blocked, timeout, login wall, etc.)."""
    try:
        resp = requests.get(
            url,
            headers={"User-Agent": "Mozilla/5.0 (compatible; FambaiCV-JobScan/1.0)"},
            timeout=8,
            allow_redirects=True,
        )
        if resp.status_code != 200 or "text/html" not in resp.headers.get("Content-Type", ""):
            return None
        soup = BeautifulSoup(resp.text, "html.parser")
        return soup, resp.url, len(resp.history)
    except requests.RequestException:
        return None


def extract_visible_text(soup: BeautifulSoup) -> str:
    """Strips scripts/styles/nav/etc and returns plain visible text.
    Call this AFTER extract_company_name(), since that function reads
    <script type="application/ld+json"> tags that this strips out."""
    # Work on a fresh copy so we don't disturb the original soup if the
    # caller still needs it for other extraction.
    soup_copy = BeautifulSoup(str(soup), "html.parser")
    for tag in soup_copy(["script", "style", "nav", "footer", "header", "noscript"]):
        tag.decompose()
    text = soup_copy.get_text(separator=" ", strip=True)
    return re.sub(r"\s+", " ", text)[:8000]


def extract_domain(url: str) -> str:
    netloc = urlparse(url).netloc.lower()
    if netloc.startswith("www."):
        netloc = netloc[4:]
    return netloc.split(":")[0]  # strip port if present


def extract_company_name(soup: BeautifulSoup) -> Optional[str]:
    """Tries to identify which company a job ad claims to represent, in
    order of reliability:
      1. JobPosting structured data (schema.org JSON-LD) -> hiringOrganization.name
      2. og:site_name meta tag (the site's actual declared brand)
      3. <title> tag, trimmed at common separators
    """
    # 1. JSON-LD JobPosting schema
    for script in soup.find_all("script", attrs={"type": "application/ld+json"}):
        try:
            data = json.loads(script.string or "")
        except (json.JSONDecodeError, TypeError):
            continue
        items = data if isinstance(data, list) else [data]
        for item in items:
            if isinstance(item, dict) and item.get("@type") == "JobPosting":
                org = item.get("hiringOrganization")
                if isinstance(org, dict) and org.get("name"):
                    return str(org["name"]).strip()

    # 2. og:site_name
    og = soup.find("meta", attrs={"property": "og:site_name"})
    if og and og.get("content"):
        return og["content"].strip()

    # 3. <title>
    if soup.title and soup.title.string:
        title = soup.title.string.strip()
        for sep in (" - ", " | ", " :: "):
            if sep in title:
                return title.split(sep)[0].strip()
        return title if title else None

    return None


# ---------- Known company domains (non-exhaustive safety net) ----------
# This is a heuristic seed list, NOT a complete verified-employer database.
# It catches impersonation of well-known brands but will miss smaller or
# newer legitimate employers, and won't catch impersonation of a brand
# that isn't in this list. Expand this over time using real reports from
# your "Report fake jobs" feature — that's the only way this improves.

KNOWN_DOMAINS = {
    "econet": "econet.co.zw",
    "netone": "netone.co.zw",
    "ecocash": "ecocash.co.zw",
    "zimra": "zimra.co.zw",
    "cbz": "cbz.co.zw",
    "steward bank": "stewardbank.co.zw",
    "nmb bank": "nmbz.co.zw",
    "old mutual": "oldmutual.co.zw",
    "delta corporation": "deltacorporation.com",
    "vacancymail": "vacancymail.co.zw",
    "zimbajob": "zimbajob.com",
    "indeed": "indeed.com",
    "linkedin": "linkedin.com",
}

SUSPICIOUS_TLDS = (".tk", ".ml", ".ga", ".cf", ".xyz", ".top", ".click", ".work", ".loan", ".win", ".buzz")


def check_company_domain_mismatch(domain: str, claimed_company: Optional[str]) -> List[str]:
    """If the page claims to represent a known brand but isn't hosted on
    that brand's real domain, this is one of the strongest scam signals
    available without a verified-employer database."""
    if not claimed_company:
        return []

    claimed_lower = claimed_company.lower()
    warnings = []

    for brand, official_domain in KNOWN_DOMAINS.items():
        if brand not in claimed_lower:
            continue
        if domain == official_domain or domain.endswith("." + official_domain):
            continue  # matches the real domain — fine

        similarity = difflib.SequenceMatcher(None, domain, official_domain).ratio()
        brand_root = official_domain.split(".")[0]

        if similarity > 0.55 or brand_root in domain:
            warnings.append(
                f'This page claims to represent "{claimed_company}" but is hosted on '
                f'"{domain}" — not their official domain ({official_domain}). This is a '
                f"common pattern in fake job postings that impersonate real companies."
            )
        else:
            warnings.append(
                f'This page claims to represent "{claimed_company}" but is not on their '
                f"known official domain ({official_domain}). Verify independently before applying."
            )
        break  # one flag per brand match is enough

    return warnings


def check_suspicious_tld(domain: str) -> List[str]:
    if domain.endswith(SUSPICIOUS_TLDS):
        ext = domain.split(".")[-1]
        return [
            f'This site uses a ".{ext}" domain extension, commonly used for disposable '
            f"or scam websites. Treat with extra caution."
        ]
    return []


IP_DOMAIN_REGEX = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")


def check_ip_as_domain(domain: str) -> List[str]:
    """A job posting hosted directly on a raw IP address (no real domain
    name at all) is a strong scam indicator — legitimate companies don't
    do this."""
    if IP_DOMAIN_REGEX.match(domain):
        return [
            "This link uses a raw IP address instead of a proper company website "
            "domain. Legitimate employers do not host job postings this way — "
            "this is a strong scam indicator."
        ]
    return []


def check_redirect_chain(redirect_count: int) -> List[str]:
    """Long redirect chains (e.g. a shortened link bouncing through several
    intermediate pages) are sometimes used to disguise the real destination
    or to evade simple link-checking tools."""
    if redirect_count >= 3:
        return [
            f"This link redirected {redirect_count} times before reaching its final "
            f"destination. Long redirect chains are sometimes used to hide where a "
            f"link actually leads."
        ]
    return []


def check_brand_lookalike_domain(domain: str) -> List[str]:
    """Domain-structure check, independent of extracted company text. Catches
    cases where the page doesn't explicitly state a company name anywhere
    (no JobPosting schema, no og:site_name, generic <title>) but the domain
    itself contains a known brand name without being that brand's real
    domain — e.g. 'econet-careers-zw.tk' or 'netone.fake-jobs.com'."""
    warnings = []
    for brand, official_domain in KNOWN_DOMAINS.items():
        brand_root = official_domain.split(".")[0]
        if brand_root in domain and domain != official_domain and not domain.endswith("." + official_domain):
            warnings.append(
                f'This domain ("{domain}") contains "{brand_root}" but is not the official '
                f"domain for {brand.title()} ({official_domain}). This pattern is often used "
                f"to impersonate well-known companies."
            )
    return warnings


def check_domain_age(domain: str) -> List[str]:
    """Best-effort WHOIS lookup. Fails silently (no warning, no penalty) if
    WHOIS is unavailable or the lookup is blocked — we never penalize a job
    ad just because we couldn't check its domain age."""
    if not WHOIS_AVAILABLE:
        return []
    try:
        w = whois_lib.whois(domain)
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        if not isinstance(creation, datetime):
            return []
        age_days = (datetime.utcnow() - creation).days
        if age_days < 30:
            return [
                "This website's domain was registered less than a month ago. "
                "Newly created domains are frequently used for scam job postings."
            ]
        if age_days < 90:
            return [
                "This website's domain is less than 3 months old. Be cautious, "
                "especially if it claims to represent an established company."
            ]
        return []
    except Exception:
        return []  # WHOIS lookup failed/blocked — don't penalize for this


# ---------- Scam phrase detection (unchanged from previous version) ----------

PAYMENT_SCAM_PHRASES = [
    "registration fee", "training fee", "processing fee", "application fee",
    "send ecocash", "send your ecocash", "send mobile money", "send money to",
    "pay before", "pay a fee", "pay to secure", "deposit required",
    "pay for uniform", "pay for training kit", "visa sponsorship fee",
    "agent fee", "pay registration", "kindly pay", "fee is required",
    "send $", "send your payment", "courier fee", "shipping fee",
    "western union", "moneygram", "joining fee", "registration code",
    "send your bank details", "send your account number", "clearance fee",
]

PROMISE_SCAM_PHRASES = [
    "guaranteed job", "guaranteed employment", "guaranteed income",
    "no interview required", "no experience needed earn", "earn from home easily",
    "100% guaranteed", "instant hiring", "hired immediately", "no cv needed",
]

URGENCY_PHRASES = [
    "hurry", "limited slots", "act now", "act fast", "immediate start",
    "only a few positions left", "apply within 24 hours", "today only",
]

VAGUE_CONTACT_PHRASES = [
    "whatsapp only", "send your cv to this number", "contact us on whatsapp",
    "dm to apply", "inbox us",
]

FREE_EMAIL_DOMAINS = {"gmail.com", "yahoo.com", "outlook.com", "hotmail.com"}

EMAIL_REGEX = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
PHONE_REGEX = re.compile(r"(?:\+263|0)(7[0-8])\d{7}")
SALARY_REGEX = re.compile(r"(usd|us\$|\$|zwl|salary|stipend|remuneration)\s*[:\-]?\s*\d", re.IGNORECASE)
LOCATION_HINTS = re.compile(
    r"\b(harare|bulawayo|gweru|mutare|masvingo|chitungwiza|kwekwe|kadoma|"
    r"zvishavane|chinhoyi|bindura|victoria falls|location|based in|remote|"
    r"hybrid|on-site)\b",
    re.IGNORECASE,
)
COMPANY_NAME_HINTS = re.compile(
    r"\b(pvt ltd|private limited|ltd|limited|inc|company|enterprises|group|"
    r"holdings|solutions)\b",
    re.IGNORECASE,
)
EXCESSIVE_CAPS_OR_EMOJI = re.compile(r"[A-Z]{6,}|[\U0001F300-\U0001FAFF]{3,}")


def _find_matches(phrases: List[str], lower_text: str) -> List[str]:
    return [p for p in phrases if p in lower_text]


def score_job_text(text: str) -> Tuple[int, List[str], int]:
    """Returns (score, warnings, signal_count). signal_count is how many
    concrete identifying details (email, phone, salary, location, company
    name) were found — used to report an honest confidence level rather
    than presenting a score based on a one-line ad the same way as a score
    based on a full, detailed posting."""
    score = 100
    warnings: List[str] = []
    signal_count = 0
    lower = text.lower()

    payment_hits = _find_matches(PAYMENT_SCAM_PHRASES, lower)
    if payment_hits:
        score -= 45
        for phrase in payment_hits[:3]:
            warnings.append(
                f'Mentions "{phrase}" — never pay money or send EcoCash/mobile '
                f"money to apply for or secure a job. Legitimate employers do not "
                f"charge job seekers."
            )

    promise_hits = _find_matches(PROMISE_SCAM_PHRASES, lower)
    if promise_hits:
        score -= 20
        warnings.append(
            f'Uses an unrealistic promise ("{promise_hits[0]}"). Be skeptical of '
            f"jobs that guarantee hiring with no interview or selection process."
        )

    urgency_hits = _find_matches(URGENCY_PHRASES, lower)
    if urgency_hits:
        score -= 8
        warnings.append(
            "Uses urgency language (e.g. 'hurry', 'limited slots'). Scammers "
            "often pressure quick decisions to prevent you from checking the offer."
        )

    emails = EMAIL_REGEX.findall(text)
    phones = PHONE_REGEX.findall(text)
    vague_contact_hits = _find_matches(VAGUE_CONTACT_PHRASES, lower)

    if emails:
        signal_count += 1
        domain_part = emails[0].split("@")[-1].lower()
        if domain_part in FREE_EMAIL_DOMAINS:
            score -= 10
            warnings.append(
                "Contact email uses a free webmail service rather than a company "
                "domain — genuine employers usually use a company email address."
            )
    else:
        score -= 12
        warnings.append("No email address found — verify the company independently before applying.")

    if phones:
        signal_count += 1
        if not emails:
            score -= 10
            warnings.append(
                "Only a phone number is provided, with no email or company details. "
                "Be cautious of phone-only or WhatsApp-only job ads."
            )

    if vague_contact_hits:
        score -= 8
        warnings.append("Asks you to apply only via WhatsApp/DM with no formal application process.")

    if SALARY_REGEX.search(text):
        signal_count += 1
    else:
        score -= 10
        warnings.append("No clear salary or pay information mentioned.")

    if LOCATION_HINTS.search(text):
        signal_count += 1
    else:
        score -= 8
        warnings.append("No clear location mentioned for this job.")

    if COMPANY_NAME_HINTS.search(text):
        signal_count += 1
    else:
        score -= 7
        warnings.append("No identifiable company/business name found in this ad.")

    if EXCESSIVE_CAPS_OR_EMOJI.search(text):
        score -= 5
        warnings.append("Ad uses excessive capital letters or emojis, common in spam-style postings.")

    score = max(0, min(100, score))
    return score, warnings, signal_count


def _confidence_level(text: str, signal_count: int) -> str:
    """Honest self-assessment of how much to trust this particular score.
    A two-line ad with no email, phone, salary, or location gives us almost
    nothing to judge — that should read as low confidence, not the same
    polish as a fully detailed posting."""
    word_count = len(text.split())
    if word_count < 15 or signal_count == 0:
        return "low"
    if signal_count <= 2:
        return "medium"
    return "high"


def _label_for_score(score: int) -> str:
    if score >= 70:
        return "Likely genuine"
    if score >= 40:
        return "Use caution"
    return "High risk"


# ---------- Endpoint ----------

@app.post("/api/job-scan", response_model=JobScanResponse)
def job_scan(payload: JobScanRequest):
    raw_input = payload.input.strip()

    if not URL_PATTERN.match(raw_input):
        # Raw pasted text — no domain to check, just run the text rules.
        score, warnings, signal_count = score_job_text(raw_input)
        confidence = _confidence_level(raw_input, signal_count)
        return JobScanResponse(
            score=score, label=_label_for_score(score), warnings=warnings,
            source_type="text", confidence=confidence,
        )

    # ---- URL path ----
    fetch_result = fetch_page(raw_input)
    if fetch_result is None:
        return JobScanResponse(
            score=0,
            label="Could not verify",
            warnings=[
                "We couldn't access this link directly (it may be blocked or "
                "require login, e.g. Facebook/WhatsApp). Please copy and paste "
                "the full job ad text instead for an accurate scan."
            ],
            source_type="url",
            fetch_failed=True,
        )

    soup, final_url, redirect_count = fetch_result
    # Use the FINAL resolved URL's domain — important for shortened links
    # (bit.ly, tinyurl, etc.) that redirect to the real destination.
    domain = extract_domain(final_url)
    detected_company = extract_company_name(soup)  # must run BEFORE stripping scripts
    visible_text = extract_visible_text(soup)

    # Base score from the text rules engine.
    score, warnings, signal_count = score_job_text(visible_text)
    confidence = _confidence_level(visible_text, signal_count)
    if detected_company:
        # Being able to identify who the page claims to represent is itself
        # a meaningful signal, even before checking if that claim is true.
        signal_count += 1
        confidence = _confidence_level(visible_text, signal_count)

    # Domain/company verification checks — these are strong signals, so they
    # go to the front of the warnings list and carry meaningful penalties.
    # Two independent detection paths feed into one combined brand-impersonation
    # check, so a single match doesn't get penalized twice:
    #   1. text-based: does the page's CLAIMED company name mismatch the domain?
    #   2. structure-based: does the domain ITSELF contain a brand name it
    #      shouldn't (catches pages with no extractable company name at all)?
    brand_warnings = check_company_domain_mismatch(domain, detected_company) + check_brand_lookalike_domain(domain)
    if brand_warnings:
        score -= 30

    ip_warnings = check_ip_as_domain(domain)
    if ip_warnings:
        score -= 25

    tld_warnings = check_suspicious_tld(domain)
    if tld_warnings:
        score -= 10

    redirect_warnings = check_redirect_chain(redirect_count)
    if redirect_warnings:
        score -= 10

    age_warnings = check_domain_age(domain)
    if age_warnings:
        score -= 15 if "less than a month" in age_warnings[0] else 8

    warnings = brand_warnings + ip_warnings + tld_warnings + redirect_warnings + age_warnings + warnings
    score = max(0, min(100, score))

    return JobScanResponse(
        score=score,
        label=_label_for_score(score),
        warnings=warnings,
        source_type="url",
        domain=domain,
        detected_company=detected_company,
        confidence=confidence,
    )


@app.get("/")
def health_check():
    return {"status": "ok", "service": "Fambai CV Job Scan"}