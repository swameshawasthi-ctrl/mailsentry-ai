from typing import List
from pydantic import BaseModel, Field
from .email_parser import ParsedEmail
from .domain_checker import DomainAnalysisResult
from .phishing_detector import PhishingAnalysisResult

class SecurityAssessment(BaseModel):
    threat_level: str
    risk_score: int
    attack_category: str
    summary: str
    evidence_items: List[str] = Field(default_factory=list)
    actionable_recommendations: List[str] = Field(default_factory=list)
    formatted_chat_report: str = ""

def calculate_risk_score(
    email: ParsedEmail,
    domain_results: List[DomainAnalysisResult],
    phish_res: PhishingAnalysisResult
) -> int:
    """
    Computes weighted forensic risk score from 0 to 100.
    """
    score = 0

    # Base on phishing detection confidence
    if phish_res.is_phishing:
        score += int(phish_res.confidence * 45)
    else:
        score += int((1.0 - phish_res.confidence) * 15)

    # Typosquatting / Domain spoofing (+25)
    if any(d.typosquatting_detected for d in domain_results):
        score += 25

    # Suspicious TLD / Lack of MX (+15)
    if any(d.suspicious_tld or d.has_valid_mx is False for d in domain_results):
        score += 15

    # Urgency cues (+15)
    if email.urgency_cues:
        score += min(len(email.urgency_cues) * 7, 15)

    # Credential theft intent (+20)
    if email.credential_cues:
        score += 20

    # Sender domain mismatch with link (+15)
    if any("mismatch" in v.lower() for v in phish_res.detected_vectors):
        score += 15

    return min(max(score, 5), 98) if phish_res.is_phishing else min(score, 25)

def generate_investigation_report(
    email: ParsedEmail,
    domain_results: List[DomainAnalysisResult],
    phish_res: PhishingAnalysisResult
) -> SecurityAssessment:
    """
    Synthesizes tools output into an executive security assessment and ACP chat markdown.
    """
    score = calculate_risk_score(email, domain_results, phish_res)

    # Determine Threat Level
    if score >= 80:
        threat_level = "CRITICAL PHISHING 🔴"
    elif score >= 50:
        threat_level = "HIGH RISK 🟠"
    elif score >= 25:
        threat_level = "SUSPICIOUS 🟡"
    else:
        threat_level = "SAFE / CLEAN 🟢"

    # Evidence consolidation
    evidence = []
    if email.sender_email:
        evidence.append(f"**Sender Identity:** `{email.sender_email}`")
    
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

    # Actionable advice
    recommendations = []
    if phish_res.is_phishing:
        recommendations.append("🚫 **DO NOT CLICK** any embedded links or download attachments.")
        recommendations.append("🔒 **Do NOT enter passwords**, OTPs, or financial details.")
        if any(d.impersonated_target for d in domain_results):
            impersonated = [d.impersonated_target for d in domain_results if d.impersonated_target][0]
            recommendations.append(f"🌐 Access the legitimate service directly via official app or by typing `https://www.{impersonated}.com` manually.")
        recommendations.append("🛡️ Forward this message to your organization's Security Operations Center (SOC).")
        recommendations.append("🗑️ Delete or move the email to Spam/Quarantine immediately.")
    else:
        recommendations.append("✅ Email displays normal baseline indicators.")
        recommendations.append("💡 Standard security hygiene: Always verify unexpected requests via a separate trusted channel.")

    summary = (
        f"MailSentry AI completed automated threat forensics. "
        f"Classification: **{phish_res.attack_category}** with a threat risk score of **{score}/100**."
    )

    # Render polished markdown for ASI:One chat
    chat_markdown = f"""### 🛡️ MAILSENTRY AI — Threat Investigation Report

| Metric | Assessment |
| :--- | :--- |
| **Threat Level** | **{threat_level}** |
| **Risk Score** | **{score} / 100** |
| **Category** | {phish_res.attack_category} |
| **Sender** | `{email.sender_email or 'Unknown'}` |

---

#### 🔍 Forensic Evidence & Findings:
"""
    for item in evidence:
        chat_markdown += f"- {item}\n"

    if phish_res.ai_reasoning:
        chat_markdown += f"\n> **Analyst Reasoning:** {phish_res.ai_reasoning}\n"

    chat_markdown += "\n#### ⚡ Recommended Actions:\n"
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
        formatted_chat_report=chat_markdown
    )
