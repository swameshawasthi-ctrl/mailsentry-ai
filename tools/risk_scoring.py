from typing import List, Optional, Dict, Any
from urllib.parse import urlparse
from pydantic import BaseModel, Field
from .email_parser import ParsedEmail
from .domain_checker import DomainAnalysisResult, extract_domain_from_url
from .phishing_detector import PhishingAnalysisResult
from .header_forensics import HeaderForensicsResult

class SecurityAssessment(BaseModel):
    threat_level: str
    risk_score: int
    attack_category: str
    summary: str
    evidence_items: List[str] = Field(default_factory=list)
    actionable_recommendations: List[str] = Field(default_factory=list)
    mitre_tactics: List[str] = Field(default_factory=list)
    extracted_links_breakdown: List[Dict[str, Any]] = Field(default_factory=list)
    originating_ip: Optional[str] = None
    ip_country: Optional[str] = None
    spf_status: Optional[str] = None
    dkim_status: Optional[str] = None
    formatted_chat_report: str = ""

def calculate_risk_score(
    email: ParsedEmail,
    domain_results: List[DomainAnalysisResult],
    phish_res: PhishingAnalysisResult,
    header_forensics: Optional[HeaderForensicsResult] = None
) -> int:
    score = 0
    if phish_res.is_phishing:
        score += int(phish_res.confidence * 40)
    else:
        score += int((1.0 - phish_res.confidence) * 15)

    if any(d.typosquatting_detected for d in domain_results):
        score += 25

    if any(d.suspicious_tld or d.has_valid_mx is False for d in domain_results):
        score += 15

    if email.urgency_cues:
        score += min(len(email.urgency_cues) * 6, 15)

    if email.credential_cues:
        score += 20

    if any("mismatch" in v.lower() for v in phish_res.detected_vectors):
        score += 15

    if header_forensics:
        if header_forensics.spf_status in ["fail", "softfail", "hardfail"]:
            score += 15
        if header_forensics.dkim_status in ["fail"]:
            score += 15

    return min(max(score, 5), 99) if phish_res.is_phishing else min(score, 25)

def get_mitre_mapping(
    email: ParsedEmail,
    domain_results: List[DomainAnalysisResult],
    phish_res: PhishingAnalysisResult
) -> List[str]:
    mitre = []
    if phish_res.is_phishing:
        mitre.append("T1566: Phishing (Initial Access)")
        if email.extracted_urls:
            mitre.append("T1566.001: Spearphishing Link (Initial Access)")
        if any(d.typosquatting_detected for d in domain_results):
            mitre.append("T1036.005: Masquerading: Match Legitimate Brand (Defense Evasion)")
        if email.credential_cues:
            mitre.append("T1598.003: Phishing for Information: Credentials (Reconnaissance)")
        if email.urgency_cues:
            mitre.append("T1204.001: User Execution: Malicious Link (Social Engineering)")
    return mitre

def decompose_urls(urls: List[str], domain_results: List[DomainAnalysisResult]) -> List[Dict[str, Any]]:
    breakdown = []
    typo_map = {d.domain: d.impersonated_target for d in domain_results if d.typosquatting_detected}

    for u in urls:
        parsed = urlparse(u)
        host = (parsed.netloc or "").split(":")[0].lower()
        is_typo = host in typo_map
        breakdown.append({
            "url": u,
            "host": host,
            "path": parsed.path or "/",
            "protocol": parsed.scheme or "http",
            "is_typosquatting": is_typo,
            "mimicked_brand": typo_map.get(host),
            "verdict": "MALICIOUS" if is_typo else "UNKNOWN/EXTERNAL"
        })
    return breakdown

def generate_investigation_report(
    email: ParsedEmail,
    domain_results: List[DomainAnalysisResult],
    phish_res: PhishingAnalysisResult,
    header_forensics: Optional[HeaderForensicsResult] = None
) -> SecurityAssessment:
    score = calculate_risk_score(email, domain_results, phish_res, header_forensics)

    if score >= 80:
        threat_level = "CRITICAL PHISHING 🔴"
    elif score >= 50:
        threat_level = "HIGH RISK 🟠"
    elif score >= 25:
        threat_level = "SUSPICIOUS 🟡"
    else:
        threat_level = "SAFE / CLEAN 🟢"

    evidence = []
    if email.sender_email:
        evidence.append(f"**Sender Identity:** `{email.sender_email}`")
    
    origin_ip = None
    ip_country = None
    if header_forensics:
        origin_ip = header_forensics.originating_ip
        ip_country = header_forensics.ip_country
        if header_forensics.originating_ip:
            geo_info = f" ({header_forensics.ip_country})" if header_forensics.ip_country else ""
            evidence.append(f"**Originating IP:** `{header_forensics.originating_ip}`{geo_info}")
        for flag in header_forensics.flags:
            if flag not in evidence:
                evidence.append(f"**Header Forensics:** {flag}")

    for d in domain_results:
        if d.typosquatting_detected:
            evidence.append(f"**Domain Deception:** `{d.domain}` mimics `{d.impersonated_target}` (Typosquatting)")
        if d.suspicious_tld:
            evidence.append(f"**High-Abuse TLD:** `{d.domain}` uses risky extension")
        if d.has_valid_mx is False:
            evidence.append(f"**DNS Anomaly:** Domain `{d.domain}` lacks valid MX records")

    for v in phish_res.detected_vectors:
        if v not in evidence:
            evidence.append(f"**Attack Indicator:** {v}")

    recommendations = []
    if phish_res.is_phishing:
        recommendations.append("DO NOT CLICK embedded links or download attachments.")
        recommendations.append("Do NOT submit passwords, MFA tokens, or corporate credentials.")
        if any(d.impersonated_target for d in domain_results):
            impersonated = [d.impersonated_target for d in domain_results if d.impersonated_target][0]
            recommendations.append(f"Navigate to authentic portal manually at https://www.{impersonated}.com.")
        recommendations.append("Quarantine message and submit sender domain to perimeter firewall blacklist.")
        recommendations.append("Revoke active user sessions if credentials were previously disclosed.")
    else:
        recommendations.append("Email displays authentic baseline signals.")
        recommendations.append("Maintain routine security hygiene: Verify out-of-band wire requests.")

    summary = (
        f"MailSentry AI completed automated threat forensics. "
        f"Classification: **{phish_res.attack_category}** with a threat risk score of **{score}/100**."
    )

    mitre_tactics = get_mitre_mapping(email, domain_results, phish_res)
    links_breakdown = decompose_urls(email.extracted_urls, domain_results)

    # Polished ACP Markdown
    chat_markdown = f"""### 🛡️ MAILSENTRY AI — Threat Investigation Report

| Metric | Assessment |
| :--- | :--- |
| **Threat Level** | **{threat_level}** |
| **Risk Score** | **{score} / 100** |
| **Category** | {phish_res.attack_category} |
| **Sender** | `{email.sender_email or 'Unknown'}` |
"""
    if origin_ip:
        chat_markdown += f"| **Originating IP** | `{origin_ip}` ({ip_country or 'Global'}) |\n"

    chat_markdown += """
---

#### 🔍 Forensic Evidence Chain:
"""
    for item in evidence:
        chat_markdown += f"- {item}\n"

    if mitre_tactics:
        chat_markdown += "\n#### 🎯 MITRE ATT&CK Mapping:\n"
        for t in mitre_tactics:
            chat_markdown += f"- `{t}`\n"

    if phish_res.ai_reasoning:
        chat_markdown += f"\n> **Analyst Reasoning:** {phish_res.ai_reasoning}\n"

    chat_markdown += "\n#### ⚡ Recommended Remediation:\n"
    for rec in recommendations:
        chat_markdown += f"- {rec}\n"

    chat_markdown += "\n*Powered by MailSentry AI Sentinel on Fetch.ai Network & ASI:One*"

    return SecurityAssessment(
        threat_level=threat_level,
        risk_score=score,
        attack_category=phish_res.attack_category,
        summary=summary,
        evidence_items=evidence,
        actionable_recommendations=recommendations,
        mitre_tactics=mitre_tactics,
        extracted_links_breakdown=links_breakdown,
        originating_ip=origin_ip,
        ip_country=ip_country,
        spf_status=header_forensics.spf_status if header_forensics else None,
        dkim_status=header_forensics.dkim_status if header_forensics else None,
        formatted_chat_report=chat_markdown
    )
