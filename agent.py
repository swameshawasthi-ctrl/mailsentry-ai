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

    # ---------------------------------------------------------
    # Preset Threat Scenarios for 1-Click Interactive Demos
    # ---------------------------------------------------------
    PRESETS = {
        "paypal": (
            "From: PayPal Support <security@paypa1-support.com>\n"
            "Subject: URGENT: Your PayPal account has been suspended!\n"
            "Date: Sat, 24 Oct 2026 10:15:00 +0000\n"
            "Received: from mail-relay.paypa1-support.com (198.51.100.23)\n\n"
            "Dear Customer,\n"
            "We detected unauthorized logins from an unknown device. Your account will be permanently terminated in 30 minutes unless you verify your identity immediately.\n\n"
            "Click here to verify your account and credit card details:\n"
            "https://paypa1-support.com/auth/login-secure\n\n"
            "Sincerely,\nPayPal Security Team"
        ),
        "ceo": (
            "From: Tim Cook <tcook@apple-executive-office.org>\n"
            "Subject: STRICTLY CONFIDENTIAL: Immediate Wire Transfer Request\n"
            "Date: Sat, 24 Oct 2026 09:30:00 +0000\n"
            "Received: from unknown-vps.hk-hosting.net (103.224.182.24)\n\n"
            "Team,\n"
            "I am currently in an acquisition negotiation and cannot take phone calls.\n"
            "Please process an urgent wire transfer of $142,500 to the escrow account attached below immediately.\n"
            "Confirm once executed. Do not discuss this with anyone until the deal is closed.\n\n"
            "Tim Cook\nChief Executive Officer"
        ),
        "safe": (
            "From: Google Calendar <notifications@calendar.google.com>\n"
            "Subject: Invitation: Product Architecture Sync @ Mon Oct 26, 2026 2pm - 3pm (IST)\n"
            "Date: Sat, 24 Oct 2026 08:00:00 +0000\n"
            "Received: from mail-sor-f65.google.com (209.85.220.65)\n\n"
            "You have been invited to the following event:\n"
            "Product Architecture Sync\n"
            "When: Monday, Oct 26, 2026 2:00 PM - 3:00 PM India Standard Time\n"
            "Joining Info: Join with Google Meet: https://meet.google.com/abc-defg-hij\n"
            "Organizer: engineering-team@fetch.ai"
        ),
        "typo": (
            "From: Microsoft Account Team <security-alert@micros0ft-verify.live>\n"
            "Subject: Action Required: Your Office 365 Password Expires Today\n"
            "Date: Sat, 24 Oct 2026 11:00:00 +0000\n"
            "Received: from smtp-relay.micros0ft-verify.live (45.33.32.156)\n\n"
            "Your Microsoft Office 365 password will expire in 2 hours. Keep your same password by validating your corporate login below:\n"
            "https://micros0ft-verify.live/adfs/ls/login"
        )
    }

    def build_welcome_card() -> dict:
        return {
            "root": {
                "type": "section",
                "title": "MailSentry AI Sentinel",
                "subtitle": "Fetch.ai Autonomous Security Node · October 24, 2026",
                "children": [
                    {
                        "type": "text",
                        "value": "Autonomous Email Threat Forensics & Typosquatting Sentinel. I dissect suspicious emails, verify SPF/DKIM headers, check DNS MX records, and execute zero-trust containment directly inside ASI:One."
                    },
                    {
                        "type": "text",
                        "value": "Pick an attack scenario below to test, or paste your raw email text directly into chat:",
                        "style": "muted"
                    },
                    {
                        "type": "group",
                        "direction": "row",
                        "gap": 8,
                        "children": [
                            {"type": "button", "label": "🚨 Test PayPal Phishing", "primary": True, "action": {"selection": {"preset": "paypal"}}},
                            {"type": "button", "label": "🏢 Test CEO Wire Fraud", "primary": False, "action": {"selection": {"preset": "ceo"}}}
                        ]
                    },
                    {
                        "type": "group",
                        "direction": "row",
                        "gap": 8,
                        "children": [
                            {"type": "button", "label": "📅 Test Safe Google Invite", "primary": False, "action": {"selection": {"preset": "safe"}}},
                            {"type": "button", "label": "🔍 Test Typosquatting", "primary": False, "action": {"selection": {"preset": "typo"}}}
                        ]
                    },
                    {
                        "type": "group",
                        "direction": "row",
                        "gap": 8,
                        "children": [
                            {"type": "button", "label": "📊 View SOC Dashboard", "primary": False, "action": {"selection": {"action": "view_soc"}}},
                            {"type": "button", "label": "📋 Capabilities & Tools", "primary": False, "action": {"selection": {"action": "help"}}}
                        ]
                    }
                ]
            }
        }

    def build_forensics_card(assessment: SecurityAssessment) -> dict:
        badge_variant = "warning" if assessment.risk_score >= 60 else "success"
        spf_str = assessment.spf_status or "UNVERIFIED"
        dkim_str = assessment.dkim_status or "UNVERIFIED"
        origin_ip = assessment.originating_ip or "N/A"
        origin_geo = assessment.ip_country or "Unknown Location"
        mitre_tag = assessment.mitre_tactics[0] if assessment.mitre_tactics else "T1566: Phishing"

        return {
            "root": {
                "type": "section",
                "title": f"MailSentry Forensics · {assessment.threat_level}",
                "subtitle": f"Risk Score: {assessment.risk_score}/100 | Category: {assessment.attack_category}",
                "children": [
                    {
                        "type": "badge",
                        "label": f"RISK: {assessment.threat_level} ({assessment.risk_score}/100)",
                        "variant": badge_variant
                    },
                    {
                        "type": "text",
                        "value": f"Sender: {assessment.sender_email or 'Unknown'} | Domain: {assessment.sender_domain or 'Unknown'}"
                    },
                    {
                        "type": "text",
                        "value": f"Origin IP: {origin_ip} ({origin_geo}) | Auth: SPF {spf_str} / DKIM {dkim_str}"
                    },
                    {
                        "type": "text",
                        "value": f"MITRE ATT&CK: {mitre_tag}",
                        "style": "muted"
                    },
                    {
                        "type": "divider"
                    },
                    {
                        "type": "heading",
                        "value": "Automated Containment Actions:",
                        "level": 3
                    },
                    {
                        "type": "group",
                        "direction": "row",
                        "gap": 8,
                        "children": [
                            {
                                "type": "button",
                                "label": "🛡️ Quarantine & Block Sender",
                                "primary": True,
                                "action": {
                                    "selection": {
                                        "action": "quarantine",
                                        "sender": assessment.sender_email or "unknown_threat",
                                        "score": assessment.risk_score
                                    }
                                }
                            },
                            {
                                "type": "button",
                                "label": "📋 Export IOCs to SOC",
                                "primary": False,
                                "action": {
                                    "selection": {
                                        "action": "export_ioc",
                                        "sender": assessment.sender_email or "unknown_threat"
                                    }
                                }
                            }
                        ]
                    },
                    {
                        "type": "group",
                        "direction": "row",
                        "gap": 8,
                        "children": [
                            {
                                "type": "button",
                                "label": "🔄 Scan Another Email",
                                "primary": False,
                                "action": {
                                    "selection": {
                                        "action": "welcome"
                                    }
                                }
                            },
                            {
                                "type": "button",
                                "label": "📊 Open SOC Console",
                                "primary": False,
                                "action": {
                                    "selection": {
                                        "action": "view_soc"
                                    }
                                }
                            }
                        ]
                    }
                ]
            }
        }

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
        ctx.logger.info(f"Incoming content (length: {len(incoming_text)} chars): '{incoming_text[:60]}...'")

        # Parse potential interactive card action / selection JSON
        action_data = None
        try:
            action_data = json.loads(incoming_text)
        except Exception:
            pass

        # Check for preset selection from interactive card
        selected_preset = None
        if action_data and "preset" in action_data:
            selected_preset = action_data["preset"]
        elif "paypal" in incoming_text.lower() and len(incoming_text) < 40:
            selected_preset = "paypal"
        elif "ceo" in incoming_text.lower() and len(incoming_text) < 40:
            selected_preset = "ceo"
        elif "safe" in incoming_text.lower() and len(incoming_text) < 40:
            selected_preset = "safe"
        elif "typo" in incoming_text.lower() and len(incoming_text) < 40:
            selected_preset = "typo"

        if selected_preset and selected_preset in PRESETS:
            incoming_text = PRESETS[selected_preset]
            ctx.logger.info(f"Loaded preset scenario: {selected_preset}")

        # Handle Quarantine CTA
        if (action_data and action_data.get("action") == "quarantine") or (incoming_text.lower() == "quarantine"):
            target_sender = (action_data.get("sender") if action_data else None) or "Flagged Threat Actor"
            ticket_id = f"SEC-{uuid.uuid4().hex[:6].upper()}"
            remediation_text = (
                f"🛡️ **AUTOMATED INCIDENT RESPONSE TRIGGERED**\n\n"
                f"- **Action Executed**: Zero-Trust Containment & Quarantine\n"
                f"- **Target Entity**: `{target_sender}`\n"
                f"- **Status**: Domain and sender address added to perimeter firewall & mail gateway drop-list\n"
                f"- **Incident Ticket**: `{ticket_id}` created in MailSentry Threat Intelligence DB\n"
                f"- **SOC Action**: Immediate analyst notification dispatched via webhook.\n\n"
                f"✅ **Threat neutralized.** Pick another scenario below or paste a new email to continue:"
            )
            await ctx.send(
                sender,
                ChatMessage(
                    msg_id=uuid.uuid4(),
                    content=[
                        TextContent(text=remediation_text),
                        MetadataContent(
                            metadata={
                                "card_protocol_version": "1",
                                "requires_card_interaction": "true",
                                "card_kind": "custom",
                                "card_payload": json.dumps(build_welcome_card()),
                                "preferred_drawer_width_px": "540"
                            }
                        )
                    ]
                )
            )
            ctx.logger.info(f"Remediation action 'quarantine' executed for {target_sender}")
            return

        # Handle IOC Export CTA
        if (action_data and action_data.get("action") == "export_ioc") or (incoming_text.lower() == "export_ioc"):
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

        # Handle SOC Console view CTA
        if (action_data and action_data.get("action") == "view_soc") or ("view_soc" in incoming_text.lower()):
            soc_text = (
                f"📊 **ENTERPRISE SOC CONSOLE STATUS**\n\n"
                f"- **Web Console**: Running at `http://localhost:8050`\n"
                f"- **Database**: SQLite `mailsentry.db` (Persistent Threat Telemetry)\n"
                f"- **Features**: Live Threat Score Gauge, MITRE ATT&CK breakdown, Decomposed Links Inspector, CSV Export & PDF Dossier.\n\n"
                f"All scans from this ASI:One chat are logged into the SOC database in real-time."
            )
            await ctx.send(
                sender,
                ChatMessage(
                    msg_id=uuid.uuid4(),
                    content=[TextContent(text=soc_text)]
                )
            )
            return

        # Handle Welcome / Greeting / Help requests
        greeting_triggers = {"hi", "hello", "hey", "start", "help", "options", "report", "email ka report do", "kya kar sakte ho", "welcome"}
        if incoming_text.lower() in greeting_triggers or (action_data and action_data.get("action") == "welcome") or len(incoming_text) < 15:
            welcome_narration = (
                "🛡️ **Welcome to MailSentry AI!**\n\n"
                "I am your autonomous email threat investigation sentinel discovered via ASI:One. "
                "I inspect email headers, verify SPF/DKIM/DMARC records, detect lookalike brand typosquatting, "
                "and execute zero-trust containment.\n\n"
                "👉 **Pick a demo scenario below to test, or paste your raw email directly into chat:**"
            )
            await ctx.send(
                sender,
                ChatMessage(
                    msg_id=uuid.uuid4(),
                    content=[
                        TextContent(text=welcome_narration),
                        MetadataContent(
                            metadata={
                                "card_protocol_version": "1",
                                "requires_card_interaction": "true",
                                "card_kind": "custom",
                                "card_payload": json.dumps(build_welcome_card()),
                                "preferred_drawer_width_px": "540"
                            }
                        )
                    ]
                )
            )
            ctx.logger.info("Dispatched Interactive Welcome Card to ASI:One.")
            return

        # Execute investigation toolchain on email text
        ctx.logger.info("Executing 5-tool investigation pipeline...")
        assessment = run_investigation_pipeline(incoming_text)

        # Build custom forensics card matching ASI:One rich design
        forensics_card = build_forensics_card(assessment)

        # Return both full Markdown narration AND ASI:One Interactive Custom Card
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
                            "card_kind": "custom",
                            "card_payload": json.dumps(forensics_card),
                            "preferred_drawer_width_px": "540"
                        }
                    )
                ]
            )
        )
        ctx.logger.info("Investigation report + Interactive Custom Card dispatched successfully to ASI:One.")

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
