import os
import json
from typing import List, Optional
from pydantic import BaseModel, Field
from .email_parser import ParsedEmail
from .domain_checker import DomainAnalysisResult

class PhishingAnalysisResult(BaseModel):
    is_phishing: bool
    attack_category: str
    confidence: float
    detected_vectors: List[str] = Field(default_factory=list)
    ai_reasoning: str = ""

def heuristic_detection(email: ParsedEmail, domain_results: List[DomainAnalysisResult]) -> PhishingAnalysisResult:
    """
    Offline heuristic rule engine for detecting social engineering & phishing.
    Runs reliably even before API keys are configured.
    """
    vectors = []
    score = 0.0

    # 1. Check Urgency cues
    if email.urgency_cues:
        vectors.append(f"Artificial urgency & intimidation tactics: {', '.join(email.urgency_cues)}")
        score += 0.25 * min(len(email.urgency_cues), 2)

    # 2. Check Credential theft cues
    if email.credential_cues:
        vectors.append(f"Credential harvesting prompts: {', '.join(email.credential_cues)}")
        score += 0.35

    # 3. Check Domain Spoofing / Typosquatting
    for d_res in domain_results:
        if d_res.typosquatting_detected:
            vectors.append(f"Deceptive domain impersonation: {d_res.domain} (mimicking {d_res.impersonated_target})")
            score += 0.45
        if d_res.risk_flags:
            vectors.extend([f"[{d_res.domain}] {flag}" for flag in d_res.risk_flags if flag not in vectors])

    # 4. Check URL mismatch with sender
    if email.sender_domain and email.extracted_urls:
        for url in email.extracted_urls:
            from .domain_checker import extract_domain_from_url
            url_domain = extract_domain_from_url(url)
            if url_domain and email.sender_domain not in url_domain and url_domain not in email.sender_domain:
                vectors.append(f"Sender domain ({email.sender_domain}) does not match link destination ({url_domain})")
                score += 0.25
                break

    # Determine classification
    is_phishing = score >= 0.40 or any(d.typosquatting_detected for d in domain_results)
    
    if "Credential harvesting prompts" in str(vectors) or any("verify" in c for c in email.credential_cues):
        category = "Credential Harvesting / Account Hijacking"
    elif email.urgency_cues and any("suspend" in u or "block" in u for u in email.urgency_cues):
        category = "Urgent Account Suspension Scam"
    elif any(d.typosquatting_detected for d in domain_results):
        category = "Brand Impersonation & Typosquatting"
    elif is_phishing:
        category = "Deceptive Social Engineering"
    else:
        category = "Likely Legitimate Communication"

    confidence = min(round(score, 2), 0.99) if is_phishing else round(1.0 - score, 2)

    reasoning = (
        f"Heuristic security evaluation identified {len(vectors)} risk indicators. "
        f"Primary risk drivers: {', '.join(vectors[:3]) if vectors else 'No suspicious anomalies detected'}."
    )

    return PhishingAnalysisResult(
        is_phishing=is_phishing,
        attack_category=category,
        confidence=confidence,
        detected_vectors=vectors,
        ai_reasoning=reasoning
    )

def detect_phishing_with_llm(email: ParsedEmail, domain_results: List[DomainAnalysisResult]) -> Optional[PhishingAnalysisResult]:
    """
    Uses ASI:One / OpenAI compatible LLM API if key is configured.
    """
    api_key = os.getenv("ASI1_API_KEY") or os.getenv("OPENAI_API_KEY")
    if not api_key or api_key.strip() == "":
        return None

    try:
        from openai import OpenAI
        base_url = os.getenv("OPENAI_BASE_URL", "https://api.asi1.ai/v1")
        model = os.getenv("LLM_MODEL", "asi1-mini")

        client = OpenAI(api_key=api_key, base_url=base_url)

        domain_summary = [d.model_dump() for d in domain_results]
        prompt = f"""
You are an expert AI Email Cybersecurity Forensics Analyst. Analyze this suspicious email and domain data:
Sender: {email.sender_email} (Domain: {email.sender_domain})
Subject: {email.subject}
Extracted Links: {email.extracted_urls}
Body Preview:
{email.body[:1500]}

Domain Intelligence:
{json.dumps(domain_summary, indent=2)}

Respond ONLY in strict JSON format:
{{
  "is_phishing": true/false,
  "attack_category": "Category name (e.g. Credential Harvesting, Account Suspension Extortion, Brand Impersonation)",
  "confidence": 0.0 to 1.0,
  "detected_vectors": ["specific vector 1", "specific vector 2"],
  "ai_reasoning": "Clear 2-sentence forensic rationale explaining why this is or isn't dangerous"
}}
"""
        response = client.chat.completions.create(
            model=model,
            messages=[{"role": "user", "content": prompt}],
            response_format={"type": "json_object"},
            temperature=0.1
        )
        data = json.loads(response.choices[0].message.content)
        return PhishingAnalysisResult(
            is_phishing=data.get("is_phishing", True),
            attack_category=data.get("attack_category", "Suspicious Activity"),
            confidence=float(data.get("confidence", 0.90)),
            detected_vectors=data.get("detected_vectors", []),
            ai_reasoning=data.get("ai_reasoning", "Analyzed by ASI:One LLM engine.")
        )
    except Exception as e:
        # Fall back seamlessly to heuristics if API call fails
        return None

def detect_phishing(email: ParsedEmail, domain_results: List[DomainAnalysisResult]) -> PhishingAnalysisResult:
    """
    Dual-engine phishing detector: tries ASI:One LLM first, falls back to heuristic engine.
    """
    llm_result = detect_phishing_with_llm(email, domain_results)
    if llm_result:
        # Augment with any hard domain flags
        for d in domain_results:
            for flag in d.risk_flags:
                if flag not in llm_result.detected_vectors:
                    llm_result.detected_vectors.append(flag)
        return llm_result
    
    return heuristic_detection(email, domain_results)
