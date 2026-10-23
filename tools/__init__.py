"""
MailSentry AI - Forensic and Threat Investigation Tool Suite
"""
from .email_parser import parse_email_content, ParsedEmail
from .domain_checker import analyze_domain, DomainAnalysisResult
from .phishing_detector import detect_phishing, PhishingAnalysisResult
from .risk_scoring import generate_investigation_report, SecurityAssessment
from .header_forensics import inspect_email_headers, HeaderForensicsResult

__all__ = [
    "parse_email_content",
    "ParsedEmail",
    "analyze_domain",
    "DomainAnalysisResult",
    "detect_phishing",
    "PhishingAnalysisResult",
    "generate_investigation_report",
    "SecurityAssessment",
    "inspect_email_headers",
    "HeaderForensicsResult",
]
