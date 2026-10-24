import re
from typing import List, Dict, Optional
from urllib.parse import urlparse
from pydantic import BaseModel, Field

try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

TARGET_BRANDS = [
    "paypal", "google", "microsoft", "apple", "amazon", "netflix",
    "chase", "wellsfargo", "bankofamerica", "meta", "facebook",
    "instagram", "dropbox", "dhl", "fedex", "usps", "irs"
]

SUSPICIOUS_TLDS = [
    ".xyz", ".top", ".buzz", ".work", ".click", ".loan", ".surf",
    ".gq", ".ml", ".cf", ".tk", ".ga", ".rest", ".fit"
]

DISPOSABLE_OR_FREE_PROVIDERS = [
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com",
    "protonmail.com", "mailinator.com", "tempmail.com", "10minutemail.com"
]

class DomainAnalysisResult(BaseModel):
    domain: str
    is_impersonating: bool = False
    impersonated_target: Optional[str] = None
    typosquatting_detected: bool = False
    suspicious_tld: bool = False
    has_valid_mx: Optional[bool] = None
    is_free_provider: bool = False
    risk_flags: List[str] = Field(default_factory=list)

def extract_domain_from_url(url: str) -> str:
    """Extracts clean hostname/domain from URL."""
    try:
        parsed = urlparse(url)
        netloc = parsed.netloc or parsed.path.split("/")[0]
        # Remove port if present
        return netloc.split(":")[0].lower()
    except Exception:
        return url.lower()

def check_typosquatting(domain: str) -> tuple[bool, Optional[str]]:
    """
    Detects if a domain mimics a known reputable brand using substitutions,
    hyphens or deceptive subdomains (e.g. 'paypa1.com', 'security-paypal.xyz').
    """
    cleaned = domain.lower()
    # Normalize common number substitutions: 1 -> l/i, 0 -> o, 5 -> s, etc.
    normalized = cleaned.replace("1", "l").replace("0", "o").replace("5", "s").replace("vv", "w")

    for brand in TARGET_BRANDS:
        # Exact legitimate domain match (e.g. paypal.com or service.paypal.com)
        if cleaned == f"{brand}.com" or cleaned.endswith(f".{brand}.com"):
            continue

        # Check if normalized contains brand or cleaned contains brand with hyphens
        if brand in normalized or brand in cleaned:
            return True, brand

    return False, None

def check_dns_mx(domain: str) -> Optional[bool]:
    """Checks if domain has valid mail exchange (MX) DNS records."""
    if not DNS_AVAILABLE:
        return None
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 0.5
        resolver.lifetime = 0.5
        records = resolver.resolve(domain, "MX")
        return len(records) > 0
    except Exception:
        return False

def analyze_domain(domain: str, context_claim: Optional[str] = None) -> DomainAnalysisResult:
    """
    Forensically analyzes a domain for spoofing, deceptive branding, and DNS signals.
    """
    domain = domain.strip().lower()
    flags = []

    # Check typosquatting
    typosquat, target = check_typosquatting(domain)
    if typosquat:
        flags.append(f"Typosquatting/Lookalike mimicry of '{target}' detected")

    # Check suspicious TLD
    suspicious_tld = any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS)
    if suspicious_tld:
        flags.append("Domain uses a high-abuse/suspicious Top Level Domain (TLD)")

    # Check free provider misuse
    is_free = domain in DISPOSABLE_OR_FREE_PROVIDERS
    if is_free and context_claim and any(b in context_claim.lower() for b in TARGET_BRANDS):
        flags.append("Official company impersonated from a free/disposable webmail provider")

    # Check MX records
    has_mx = check_dns_mx(domain)
    if has_mx is False:
        flags.append("Domain lacks valid Mail Exchange (MX) DNS records")

    return DomainAnalysisResult(
        domain=domain,
        is_impersonating=bool(target),
        impersonated_target=target,
        typosquatting_detected=typosquat,
        suspicious_tld=suspicious_tld,
        has_valid_mx=has_mx,
        is_free_provider=is_free,
        risk_flags=flags
    )
