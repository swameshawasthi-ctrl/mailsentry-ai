import os
import sys
import argparse
from dotenv import load_dotenv

# Load local environment
load_dotenv()

from tools.email_parser import parse_email_content
from tools.domain_checker import analyze_domain, extract_domain_from_url
from tools.phishing_detector import detect_phishing
from tools.risk_scoring import generate_investigation_report, SecurityAssessment

def run_investigation_pipeline(raw_email_text: str) -> SecurityAssessment:
    """
    Executes end-to-end multi-tool forensic analysis on the supplied email text.
    """
    # Tool 1: Email & header parsing
    parsed_email = parse_email_content(raw_email_text)

    # Tool 2: Domain & DNS forensics for sender domain and extracted links
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

    # Tool 3: Phishing & social engineering detection
    phish_res = detect_phishing(parsed_email, domain_results)

    # Tool 4: Comprehensive risk scoring & report generation
    assessment = generate_investigation_report(parsed_email, domain_results, phish_res)
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
            chat_protocol_spec,
        )
    except ImportError:
        print("[!] uagents library not installed yet. Please run:")
        print("    pip install -r requirements.txt")
        sys.exit(1)

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
        ctx.logger.info(f"Investigating email content (length: {len(incoming_text)} chars)...")

        # Execute investigation toolchain
        assessment = run_investigation_pipeline(incoming_text)

        # Return structured analysis report to ASI:One
        await ctx.send(
            sender,
            ChatMessage(
                msg_id=ctx.get_random_uuid(),
                content=[TextContent(text=assessment.formatted_chat_report)]
            )
        )
        ctx.logger.info("Investigation report dispatched successfully to ASI:One.")

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
