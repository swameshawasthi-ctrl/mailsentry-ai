import os
from dotenv import load_dotenv

load_dotenv()

from uagents_core.utils.registration import (
    register_chat_agent,
    RegistrationRequestCredentials,
    AgentverseRequestError,
)

def register():
    agentverse_key = os.getenv("AGENTVERSE_KEY", "").strip()
    seed_phrase = os.getenv("AGENT_SEED_PHRASE", "mailsentry-ai-autonomous-security-sentinel-2026").strip()

    if not agentverse_key:
        print("[!] Error: AGENTVERSE_KEY is missing in your .env file.")
        return

    credentials = RegistrationRequestCredentials(
        agentverse_api_key=agentverse_key,
        agent_seed_phrase=seed_phrase,
    )

    print("[*] Registering MailSentry AI with rich profile & starter prompts on Agentverse...")
    try:
        register_chat_agent(
            name="MailSentry AI",
            endpoint="https://agentverse.ai/v1/agents/mailsentry-ai",
            active=True,
            credentials=credentials,
            description="Autonomous Email Cybersecurity & Threat Forensics Agent. Detects phishing, domain typosquatting, and delivers risk reports.",
            starter_prompts=[
                "Analyze this suspicious email: Your PayPal account has been suspended in 30 minutes! Verify at https://paypa1-support.com",
                "Investigate sender security@chase-alert-update.xyz and check for typosquatting.",
                "Is this calendar invite safe? From: notifications@calendar.google.com with Meet link"
            ],
            readme="""# 🛡️ MailSentry AI — Autonomous Email Threat Investigation Sentinel

> **Official FETCH-A-THON 3.0 Agent** | Built for ASI:One & Fetch.ai Network

### 🎯 Capabilities:
- **Email & Header Parsing**: Extracts senders, reply-tos, embedded links, and urgency cues.
- **Domain & DNS Forensics**: Detects brand typosquatting (e.g. `paypa1` vs `paypal`), high-abuse TLDs, and missing MX records.
- **Phishing Detection Engine**: Identifies credential harvesting, extortion, and psychological intimidation.
- **Risk Scoring & Mitigation**: Returns an executive security assessment (0-100 risk score) with evidence and actionable recommendations.

### 💡 How to Test in ASI:One:
Paste any suspicious email or security alert into the chat, and MailSentry AI will autonomously dissect the threat!
            """,
            metadata={
                "category": "security",
                "tags": ["cybersecurity", "phishing", "threat-forensics", "email-security"],
                "is_public": "True",
            }
        )
        print("[+] SUCCESS! MailSentry AI profile updated on Agentverse & ASI:One!")
    except AgentverseRequestError as err:
        print(f"[-] Registration failed: {err}")
    except Exception as e:
        print(f"[-] Unexpected error: {e}")

if __name__ == "__main__":
    register()
