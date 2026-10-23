import re
from typing import List, Optional
from pydantic import BaseModel, Field

class ParsedEmail(BaseModel):
    raw_text: str
    sender_name: Optional[str] = None
    sender_email: Optional[str] = None
    sender_domain: Optional[str] = None
    subject: Optional[str] = None
    recipient: Optional[str] = None
    extracted_urls: List[str] = Field(default_factory=list)
    body: str = ""
    urgency_cues: List[str] = Field(default_factory=list)
    credential_cues: List[str] = Field(default_factory=list)

URGENCY_KEYWORDS = [
    "urgent", "immediately", "within 24 hours", "suspended", "terminate",
    "limited time", "critical alert", "action required", "blocked",
    "deactivated", "final warning", "30 minutes", "unauthorized activity"
]

CREDENTIAL_KEYWORDS = [
    "verify identity", "confirm password", "enter credentials", "login here",
    "verify your account", "update billing", "reset password", "security check",
    "kyc verification", "validate account", "unlock account"
]

def parse_email_content(raw_input: str) -> ParsedEmail:
    """
    Parses pasted email text, header fragments, or full RFC messages
    and extracts forensic attributes.
    """
    text = raw_input.strip()

    # 1. Extract Sender info
    sender_name = None
    sender_email = None
    sender_domain = None

    from_match = re.search(r"(?i)(?:From|Sender)\s*:\s*(.+)", text)
    if from_match:
        from_line = from_match.group(1).split("\n")[0].strip()
        # Check for "Name <email@domain.com>" format
        bracket_match = re.search(r"([^<]+)?<([a-zA-Z0-9_.+-]+@([a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+))>", from_line)
        if bracket_match:
            sender_name = (bracket_match.group(1) or "").strip()
            sender_email = bracket_match.group(2).strip().lower()
            sender_domain = bracket_match.group(3).strip().lower()
        else:
            # Simple email match in from line
            email_match = re.search(r"([a-zA-Z0-9_.+-]+@([a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+))", from_line)
            if email_match:
                sender_email = email_match.group(1).strip().lower()
                sender_domain = email_match.group(2).strip().lower()
                sender_name = from_line.replace(sender_email, "").strip(" :<>\"'")
    else:
        # Fallback: scan text for first email address
        any_email = re.search(r"\b([a-zA-Z0-9_.+-]+@([a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+))\b", text)
        if any_email:
            sender_email = any_email.group(1).lower()
            sender_domain = any_email.group(2).lower()

    # 2. Extract Subject
    subject = None
    subj_match = re.search(r"(?i)Subject\s*:\s*(.+)", text)
    if subj_match:
        subject = subj_match.group(1).split("\n")[0].strip()

    # 3. Extract Recipient
    recipient = None
    to_match = re.search(r"(?i)To\s*:\s*(.+)", text)
    if to_match:
        recipient = to_match.group(1).split("\n")[0].strip()

    # 4. Extract URLs
    url_pattern = r"https?://(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\+.~#?&//=]*)"
    extracted_urls = list(set(re.findall(url_pattern, text)))

    # 5. Extract Body (strip headers if explicitly present)
    body = text
    if from_match or subj_match:
        # Clean lines starting with headers
        cleaned_lines = []
        for line in text.splitlines():
            if re.match(r"(?i)^(From|To|Subject|Date|Cc|Bcc)\s*:", line):
                continue
            cleaned_lines.append(line)
        body = "\n".join(cleaned_lines).strip()

    # 6. Detect psychological & threat cues
    lower_text = text.lower()
    urgency_cues = [k for k in URGENCY_KEYWORDS if k in lower_text]
    credential_cues = [k for k in CREDENTIAL_KEYWORDS if k in lower_text]

    return ParsedEmail(
        raw_text=raw_input,
        sender_name=sender_name,
        sender_email=sender_email,
        sender_domain=sender_domain,
        subject=subject,
        recipient=recipient,
        extracted_urls=extracted_urls,
        body=body,
        urgency_cues=urgency_cues,
        credential_cues=credential_cues
    )
