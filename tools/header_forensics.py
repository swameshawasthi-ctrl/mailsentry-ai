import re
import ipaddress
import urllib.request
import json
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field

class HeaderForensicsResult(BaseModel):
    originating_ip: Optional[str] = None
    ip_country: Optional[str] = None
    ip_isp: Optional[str] = None
    is_private_or_loopback: bool = False
    spf_status: Optional[str] = None
    dkim_status: Optional[str] = None
    dmarc_status: Optional[str] = None
    dkim_domain: Optional[str] = None
    client_ip_match_domain: Optional[bool] = None
    flags: List[str] = Field(default_factory=list)

def extract_originating_ip(headers_text: str) -> Optional[str]:
    """
    Extracts the first public IPv4 address from the Received or X-Originating-IP header chain.
    """
    # 1. Check X-Originating-IP or X-Sender-IP
    x_ip_match = re.search(r"(?i)X-(?:Originating|Sender)-IP\s*:\s*\[?([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\]?", headers_text)
    if x_ip_match:
        return x_ip_match.group(1)

    # 2. Check Received headers from bottom to top (origin to destination)
    received_lines = re.findall(r"(?i)Received\s*:\s*from.+?\[([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\]", headers_text, re.DOTALL)
    for ip_str in reversed(received_lines):
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            if not ip_obj.is_private and not ip_obj.is_loopback:
                return ip_str
        except ValueError:
            continue

    # Fallback to any bracketed IP in text
    all_ips = re.findall(r"\[([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\]", headers_text)
    for ip_str in all_ips:
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            if not ip_obj.is_private and not ip_obj.is_loopback:
                return ip_str
        except ValueError:
            continue

    return None

def lookup_ip_geolocation(ip: str) -> tuple[Optional[str], Optional[str]]:
    """
    Performs lightweight IP lookup. Uses timeout to ensure no hanging.
    """
    try:
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.is_private or ip_obj.is_loopback:
            return "Internal/Private Network", "LAN/Private"

        url = f"https://ipapi.co/{ip}/json/"
        req = urllib.request.Request(url, headers={"User-Agent": "MailSentry-AI/1.0"})
        with urllib.request.urlopen(req, timeout=2.0) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            country = data.get("country_name") or data.get("country")
            org = data.get("org") or data.get("asn")
            return country, org
    except Exception:
        return None, None

def inspect_email_headers(raw_text: str, sender_domain: Optional[str] = None) -> HeaderForensicsResult:
    """
    Parses SPF, DKIM, DMARC authentication verdicts and traces sender IP.
    """
    flags = []

    # 1. Parse SPF
    spf_match = re.search(r"(?i)(?:Received-SPF|spf)\s*:\s*([a-zA-Z]+)", raw_text)
    spf_status = None
    if spf_match:
        spf_status = spf_match.group(1).lower()
        if spf_status in ["fail", "softfail", "hardfail"]:
            flags.append(f"SPF Authentication FAILED ({spf_status}) - Sender IP not authorized")
        elif spf_status in ["pass"]:
            pass

    # 2. Parse DKIM
    dkim_status = None
    dkim_domain = None
    dkim_match = re.search(r"(?i)dkim\s*=\s*([a-zA-Z]+)", raw_text)
    if dkim_match:
        dkim_status = dkim_match.group(1).lower()
        if dkim_status in ["fail", "neutral"]:
            flags.append(f"DKIM Cryptographic Signature Invalid ({dkim_status})")

    dkim_d_match = re.search(r"(?i)d=([a-zA-Z0-9.-]+)", raw_text)
    if dkim_d_match:
        dkim_domain = dkim_d_match.group(1).lower()
        if sender_domain and dkim_domain != sender_domain and not sender_domain.endswith(f".{dkim_domain}"):
            flags.append(f"DKIM Signing Domain ({dkim_domain}) does not match From Domain ({sender_domain})")

    # 3. Parse DMARC
    dmarc_status = None
    dmarc_match = re.search(r"(?i)dmarc\s*=\s*([a-zA-Z]+)", raw_text)
    if dmarc_match:
        dmarc_status = dmarc_match.group(1).lower()
        if dmarc_status in ["fail", "reject"]:
            flags.append(f"DMARC Policy Rejection ({dmarc_status})")

    # 4. Trace Originating IP
    origin_ip = extract_originating_ip(raw_text)
    country = None
    isp = None
    is_private = False

    if origin_ip:
        try:
            ip_obj = ipaddress.ip_address(origin_ip)
            is_private = ip_obj.is_private or ip_obj.is_loopback
            if not is_private:
                country, isp = lookup_ip_geolocation(origin_ip)
                if country:
                    flags.append(f"Sender Origin IP traced to: {origin_ip} ({country})")
        except ValueError:
            pass

    return HeaderForensicsResult(
        originating_ip=origin_ip,
        ip_country=country,
        ip_isp=isp,
        is_private_or_loopback=is_private,
        spf_status=spf_status,
        dkim_status=dkim_status,
        dmarc_status=dmarc_status,
        dkim_domain=dkim_domain,
        flags=flags
    )
