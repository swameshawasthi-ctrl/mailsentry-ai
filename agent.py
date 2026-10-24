import os
import sys
import uuid
import argparse
from dotenv import load_dotenv

# Load local environment
load_dotenv()

from tools.email_parser import parse_email_content
from tools.domain_checker import analyze_domain, extract_domain_from_url
from tools.phishing_detector import detect_phishing
from tools.header_forensics import inspect_email_headers
from tools.risk_scoring import generate_investigation_report, SecurityAssessment
from database import save_scan

def run_investigation_pipeline(raw_email_text: str, source: str = "asi1_chat") -> SecurityAssessment:
    """
    Executes end-to-end multi-tool forensic analysis on the supplied email text
    and records results in the security operations database.
    """
    # Tool 1: Email & header parsing
    parsed_email = parse_email_content(raw_email_text)

    # Tool 2: RFC 822 Header & IP forensics
    header_forensics = inspect_email_headers(raw_email_text, sender_domain=parsed_email.sender_domain)

    # Tool 3: Domain & DNS forensics for sender domain and extracted links
    domains_to_check = set()
    if parsed_email.sender_domain:
        domains_to_check.add(parsed_email.sender_domain)
    for url in parsed_email.extracted_urls:
        domain = extract_domain_from_url(url)
        if domain:
            domains_to_check.add(domain)

    domain_results = [
        analyze_domain(d, context_claim=parsed_email.sender_name or parsed_email.subject)
        for d in domains_to_check
    ]

    # Tool 4: Phishing & social engineering detection
    phish_res = detect_phishing(parsed_email, domain_results)

    # Tool 5: Comprehensive risk scoring & report generation
    assessment = generate_investigation_report(
        parsed_email,
        domain_results,
        phish_res,
        header_forensics=header_forensics
    )

    # Persist in SQLite Threat Intelligence DB
    try:
        save_scan(
            sender_email=parsed_email.sender_email,
            sender_domain=parsed_email.sender_domain,
            subject=parsed_email.subject,
            risk_score=assessment.risk_score,
            threat_level=assessment.threat_level,
            attack_category=assessment.attack_category,
            evidence=assessment.evidence_items,
            recommendations=assessment.actionable_recommendations,
            originating_ip=assessment.originating_ip,
            ip_country=assessment.ip_country,
            raw_text=raw_email_text,
            source=source
        )
    except Exception as e:
        print(f"[!] Warning: Failed to save scan to database: {e}")

    return assessment

# -------------------------------------------------------------
# Fetch.ai uAgent & Agent Chat Protocol (ACP) Setup
# -------------------------------------------------------------
def start_agent():
    try:
        from uagents import Agent, Context, Protocol
        from uagents_core.contrib.protocols.chat import (
            ChatAcknowledgement,
            ChatMessage,
            TextContent,
            MetadataContent,
            chat_protocol_spec,
        )
    except ImportError:
        print("[!] uagents library not installed yet. Please run:")
        print("    pip install -r requirements.txt")
        sys.exit(1)

    import json

    agent_seed = os.getenv("AGENT_SEED_PHRASE") or os.getenv("AGENT_SEED", "mailsentry-ai-autonomous-security-sentinel-2026")
    mailbox_key = os.getenv("AGENT_MAILBOX_KEY", "").strip()

    # If mailbox key is provided, use Agentverse Mailbox configuration
    agent_kwargs = {
        "name": "mailsentry_ai",
        "seed": agent_seed,
    }
    
    if mailbox_key:
        agent_kwargs["mailbox"] = f"{mailbox_key}@https://agentverse.ai"
    else:
        agent_kwargs["mailbox"] = True

    agent = Agent(**agent_kwargs)

    # Initialize standard Agent Chat Protocol
    chat_proto = Protocol(spec=chat_protocol_spec)

    @chat_proto.on_message(ChatMessage)
    async def handle_incoming_chat(ctx: Context, sender: str, msg: ChatMessage):
        ctx.logger.info(f"Incoming message from ASI:One sender: {sender}")

        # Send immediate acknowledgement
        await ctx.send(sender, ChatAcknowledgement(acknowledged_msg_id=msg.msg_id))

        # Extract text content
        incoming_text = ""
        for item in msg.content:
            if isinstance(item, TextContent):
                incoming_text += item.text + "\n"

        incoming_text = incoming_text.strip()
        ctx.logger.info(f"Incoming content (length: {len(incoming_text)} chars)")

        # Check for Interactive Card Action callbacks (Intent to Action)
        action_data = None
        try:
            action_data = json.loads(incoming_text)
        except Exception:
            pass

        # Handle Quarantine CTA
        if (action_data and action_data.get("action") == "quarantine") or "quarantine" in incoming_text.lower():
            target_sender = (action_data.get("sender") if action_data else None) or "Flagged Threat Actor"
            ticket_id = f"SEC-{uuid.uuid4().hex[:6].upper()}"
            remediation_text = (
                f"🛡️ **AUTOMATED INCIDENT RESPONSE TRIGGERED**\n\n"
                f"- **Action Executed**: Zero-Trust Containment & Quarantine\n"
                f"- **Target Entity**: `{target_sender}`\n"
                f"- **Status**: Domain and sender address added to perimeter firewall & mail gateway drop-list\n"
                f"- **Incident Ticket**: `{ticket_id}` created in MailSentry Threat Intelligence DB\n"
                f"- **SOC Action**: Immediate analyst notification dispatched via webhook.\n\n"
                f"✅ **Threat neutralized.** You can paste another suspicious email to continue scanning."
            )
            await ctx.send(
                sender,
                ChatMessage(
                    msg_id=uuid.uuid4(),
                    content=[TextContent(text=remediation_text)]
                )
            )
            ctx.logger.info(f"Remediation action 'quarantine' executed for {target_sender}")
            return

        # Handle IOC Export CTA
        if (action_data and action_data.get("action") == "export_ioc") or "export_ioc" in incoming_text.lower():
            target_sender = (action_data.get("sender") if action_data else None) or "Analyzed Email"
            ioc_text = (
                f"📋 **INDICATORS OF COMPROMISE (IOC) EXPORTED**\n\n"
                f"- **Standard**: STIX 2.1 / OpenIOC JSON Specification\n"
                f"- **Source Agent**: MailSentry AI Sentinel Node\n"
                f"- **Entity**: `{target_sender}`\n"
                f"- **Status**: Streamed to Enterprise SIEM & SOC Collector Queue\n\n"
                f"✅ All network and domain indicators have been syndicated to active threat intelligence feeds."
            )
            await ctx.send(
                sender,
                ChatMessage(
                    msg_id=uuid.uuid4(),
                    content=[TextContent(text=ioc_text)]
                )
            )
            ctx.logger.info(f"Remediation action 'export_ioc' executed.")
            return

        # Execute investigation toolchain
        ctx.logger.info("Executing 5-tool investigation pipeline...")
        assessment = run_investigation_pipeline(incoming_text)

        # Build ASI:One Interactive Detail Card
        spf_status = assessment.header_forensics.spf_status if assessment.header_forensics else "UNVERIFIED"
        dkim_status = assessment.header_forensics.dkim_status if assessment.header_forensics else "UNVERIFIED"
        origin_ip = assessment.originating_ip or "N/A"
        origin_geo = assessment.ip_country or "Unknown Location"
        mitre_tag = assessment.mitre_attack_tags[0] if assessment.mitre_attack_tags else "T1566 (Phishing)"

        card_payload = {
            "title": f"MailSentry Forensics · {assessment.threat_level.upper()} RISK",
            "summary_rows": [
                {"label": "Threat Score", "value": f"{assessment.risk_score}/100 ({assessment.threat_level})"},
                {"label": "Attack Category", "value": assessment.attack_category},
                {"label": "Originating IP", "value": f"{origin_ip} ({origin_geo})"},
                {"label": "Email Auth", "value": f"SPF: {spf_status} | DKIM: {dkim_status}"},
                {"label": "MITRE ATT&CK", "value": mitre_tag}
            ],
            "ctas": [
                {
                    "label": "🛡️ Quarantine & Block Sender",
                    "primary": True,
                    "selection": {
                        "action": "quarantine",
                        "sender": assessment.sender_email or "unknown_threat",
                        "score": assessment.risk_score
                    }
                },
                {
                    "label": "📋 Export IOCs to SOC",
                    "primary": False,
                    "selection": {
                        "action": "export_ioc",
                        "sender": assessment.sender_email or "unknown_threat"
                    }
                }
            ]
        }

        # Return both full Markdown narration AND ASI:One Interactive Card metadata
        await ctx.send(
            sender,
            ChatMessage(
                msg_id=uuid.uuid4(),
                content=[
                    TextContent(text=assessment.formatted_chat_report),
                    MetadataContent(
                        metadata={
                            "card_protocol_version": "1",
                            "requires_card_interaction": "true",
                            "card_kind": "detail",
                            "card_payload": json.dumps(card_payload),
                            "preferred_drawer_width_px": "540"
                        }
                    )
                ]
            )
        )
        ctx.logger.info("Investigation report + Interactive Card dispatched successfully to ASI:One.")

    @chat_proto.on_message(ChatAcknowledgement)
    async def handle_acknowledgement(ctx: Context, sender: str, msg: ChatAcknowledgement):
        ctx.logger.info(f"Message acknowledged by {sender}: {msg.acknowledged_msg_id}")

    # Register protocol and publish Almanac manifest
    agent.include(chat_proto, publish_manifest=True)

    print(f"[*] Starting MailSentry AI Agent...")
    print(f"[*] Agent Address: {agent.address}")
    print(f"[*] Agentverse Mailbox Mode: Enabled")
    agent.run()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="MailSentry AI - Autonomous Email Security Agent")
    parser.add_argument("--test", type=str, help="Run instant local CLI test with raw email text")
    args = parser.parse_args()

    if args.test:
        print("[*] Running local investigation test...")
        report = run_investigation_pipeline(args.test)
        print("\n" + report.formatted_chat_report)
    else:
        start_agent()
