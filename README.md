# 🛡️ MAILSENTRY AI — Autonomous Email Threat Forensics & Containment Sentinel

> **Official Project for FETCH-A-THON 3.0** | *ASI:One Agent Challenge: From Intent to Action*  
> Hosted by **Fetch.ai Innovation Lab**, **ASI Alliance**, and **Masters' Union**

[![Platform](https://img.shields.io/badge/Platform-Fetch.ai%20uAgents-00e676?style=for-the-badge&logo=fetch.ai&logoColor=black)](https://fetch.ai)
[![ASI:One](https://img.shields.io/badge/Powered%20By-ASI%3AOne%20Agentverse-7c4dff?style=for-the-badge&logo=openai&logoColor=white)](https://asi1.ai)
[![Protocol](https://img.shields.io/badge/Protocol-Agent%20Chat%20Protocol%20(ACP%200.3.0)-00b0ff?style=for-the-badge)](https://agentverse.ai)
[![UI Cards](https://img.shields.io/badge/UI-ASI%3AOne%20Interactive%20Cards-00e676?style=for-the-badge)](https://innovationlab.fetch.ai/resources/docs/interactive-cards/asi-interactive-cards)
[![Python](https://img.shields.io/badge/Python-3.10%20%7C%203.11%20%7C%203.12-ffd600?style=for-the-badge&logo=python&logoColor=black)](https://python.org)

---

## 📌 1. Executive Summary & Challenge Alignment

Most AI implementations stop at conversation. In high-stakes enterprise domains like cybersecurity, conversational advice alone cannot stop an ongoing phishing incident.

**MailSentry AI** is an autonomous cybersecurity investigation and incident containment agent discoverable on **[ASI:One](https://asi1.ai/)** and registered on **[Agentverse](https://agentverse.ai/)**. Rather than functioning as a passive chatbot, MailSentry AI fulfills the core hackathon theme — **From Intent to Action**:

1. **Autonomous Tool Chaining**: Upon receiving raw email text or headers, MailSentry executes a 5-tool forensic pipeline (RFC parsing, lookalike typosquatting checks, live DNS MX queries, public IP geolocation, and dual-engine AI reasoning).
2. **Intent to Action Containment**: Renders native **ASI:One Interactive Cards** directly inside the conversational chat window. With a single tap on `[🛡️ Quarantine & Block Sender]`, the user commands the agent to execute zero-trust containment, blacklist the attacker domain, and generate an enterprise incident ticket (`#SEC-XXXX`).
3. **Dual-Engine Resilience**: Built with a fail-safe architecture combining ASI:One's `asi1-mini` LLM with an offline heuristic threat classification engine for zero downtime.
4. **Enterprise SOC Integration**: Simultaneously logs all incident telemetry into a persistent SQLite Threat Intelligence Database and streams to an executive SOC Web Console.

---

## 👥 2. Team & Engineering Responsibilities

Built by team **MailSentry AI**:

* **Swamesh Awasthi** (*Backend & Agent Architecture Lead*):
  - Core Fetch.ai `uagents` agent runtime (`agent.py`) and Agent Chat Protocol (ACP 0.3.0) implementation.
  - Agentverse Mailbox mode and Almanac API manifest publishing.
  - ASI:One Interactive Custom Cards wire protocol (`MetadataContent`) and action event dispatchers.
  - FastAPI server (`server.py`) and Enterprise SOC Web Console with SQLite persistence.
* **Sujal** (*Email Forensics & Geo-Intelligence Lead*):
  - RFC 822 email parser and embedded link extractor (`tools/email_parser.py`).
  - Algorithmic domain typosquatting engine and live DNS MX resolution using `dnspython` (`tools/domain_checker.py`).
  - Header forensic analyzer (SPF, DKIM, DMARC) and public IP geolocation tracer (`tools/header_forensics.py`).
* **Asmita Tripathi** (*AI/ML & Threat Detection Lead*):
  - Dual-engine threat detection: ASI:One LLM (`asi1-mini`) prompt engineering and offline heuristic fallback (`tools/phishing_detector.py`).
  - Mathematical risk scoring algorithm (0-100 calibrated score) (`tools/risk_scoring.py`).
  - MITRE ATT&CK enterprise matrix mapping (`T1566: Phishing`, `T1036.005: Masquerading`).

---

## 🏗️ 3. End-to-End System Architecture

```
                       [ User in ASI:One Chat Window ]
                                      │
                                      ▼
                 [ Agentverse Cloud Mailbox Bridge ]
                                      │  (Agent Chat Protocol 0.3.0)
                                      ▼
                  [ MailSentry uAgent Core (agent.py) ]
                                      │
       ┌──────────────────────────────┴──────────────────────────────┐
       │                                                             │
       ▼                                                             ▼
[ Tool 1: RFC Email Parser ]                       [ Tool 2: Typosquatting & DNS ]
• From/Subject/Date extraction                     • Visual character mimicry ('paypa1' vs 'paypal')
• Embedded URL scanner                             • Live DNS MX record resolution via dnspython
       │                                                             │
       ▼                                                             ▼
[ Tool 3: Header & IP Forensics ]                  [ Tool 4: Dual-Engine Threat Reasoner ]
• SPF / DKIM / DMARC verification                  • Tier-2 SOC reasoning via ASI:One (asi1-mini)
• Public IP geolocation trace                      • Offline heuristic fallback engine
       │                                                             │
       └──────────────────────────────┬──────────────────────────────┘
                                      │
                                      ▼
                      [ Tool 5: Mathematical Risk Scoring ]
                      • Calibrated Threat Score (0 - 100)
                      • MITRE ATT&CK Enterprise Mapping
                      • Persistence to SQLite DB (mailsentry.db)
                                      │
                                      ▼
                    [ Dual-Payload Returned to ASI:One ]
                      1. Transparent Forensic Markdown Report
                      2. Native ASI:One Interactive Custom Card
                                      │
                                      ▼
                    [ User clicks: "Quarantine & Block" ]
                                      │
                                      ▼
                   [ Automated Zero-Trust Containment ]
                   • Perimeter firewall drop-list updated
                   • Incident ticket #SEC-XXXX generated
```

---

## 🔬 4. Deep-Dive: The 5 Forensic Tools Under The Hood

### Tool 1: RFC 822 Email & Header Parser (`tools/email_parser.py`)
- Unpacks raw unstructured text into structured security fields: `sender_name`, `sender_email`, `sender_domain`, `reply_to`, `subject`, and `date`.
- Scans email body with regular expressions to extract all embedded hyperlinks.
- Identifies psychological manipulation triggers:
  - **Urgency Cues**: `suspended`, `24 hours`, `immediate action`, `terminating`.
  - **Sensitive Data Cues**: `password`, `verify account`, `credit card`, `banking`.

### Tool 2: Algorithmic Typosquatting & Live DNS MX Engine (`tools/domain_checker.py`)
- **Brand Mimicry Calculation**: Detects optical character lookalikes designed to deceive human eyes:
  - `1` / `l` / `i` substitution (`paypa1.com` vs `paypal.com`)
  - `0` vs `o` (`micros0ft.com` vs `microsoft.com`)
  - `vv` vs `w` (`vvellsfargo.com` vs `wellsfargo.com`)
  - `rn` vs `m` (`arnazon.com` vs `amazon.com`)
- **Live DNS MX Resolution**: Uses `dnspython` to query authoritative nameservers for Mail Exchange (`MX`) records. Legitimate enterprise domains must publish valid MX records to receive mail. Attackers frequently use burner or staging domains lacking MX records — flagging an immediate critical threat.

### Tool 3: Header Authentication & Origin IP Geolocation (`tools/header_forensics.py`)
- **Email Authentication (SPF / DKIM / DMARC)**: Inspects `Authentication-Results` and `Received-SPF` headers to verify whether the sending IP was authorized by the domain owner.
- **Header Hop Geolocation**: Parses the RFC `Received: from ... by ...` chain, filters out RFC 1918 private network IPs (`10.x.x.x`, `192.168.x.x`), extracts the true originating public server IP, and queries geolocation to identify physical server location and hosting ASN.

### Tool 4: Dual-Engine Threat Reasoning & Resilience (`tools/phishing_detector.py`)
- **Primary Engine**: Streams forensic findings to ASI:One's `asi1-mini` LLM (`https://api.asi1.ai/v1/chat/completions`) with a structured cyber-analyst system prompt.
- **Fail-Safe Offline Engine**: If network latency or API quotas interrupt communication, the built-in offline heuristic analyzer automatically takes over, evaluating keyword weights, domain anomaly scores, and URL threat indicators with zero downtime.

### Tool 5: Mathematical Threat Formula & MITRE Mapping (`tools/risk_scoring.py`)
- **Calibrated Scoring Formula (0 - 100)**:
  $$\text{Score} = \text{Base}(10) + \text{Typosquatting}(35) + \text{PII Requests}(25) + \text{Urgency}(20) + \text{Auth Failure}(20) + \text{Missing MX}(15)$$
- **Threat Levels**:
  - `0 - 29`: **SAFE / CLEAN** 🟢
  - `30 - 59`: **SUSPICIOUS** 🟡
  - `60 - 84`: **HIGH RISK** 🟠
  - `85 - 100`: **CRITICAL PHISHING** 🔴
- **MITRE ATT&CK Mapping**:
  - `T1566: Phishing (Initial Access)`
  - `T1566.001: Spearphishing Link (Initial Access)`
  - `T1036.005: Masquerading: Match Legitimate Brand (Defense Evasion)`
  - `T1204.001: User Execution: Malicious Link (Social Engineering)`

---

## 🎴 5. ASI:One Interactive Cards (From Intent to Action)

Following the [Fetch.ai Innovation Lab Interactive Cards Specification](https://innovationlab.fetch.ai/resources/docs/interactive-cards/asi-interactive-cards), MailSentry AI implements rich UI cards using `MetadataContent` with `card_kind: "custom"`.

### Welcome / Scenario Picker Card:
When a user opens chat or asks for a report, MailSentry renders an inline interactive card with a 2-column button grid:
- `🚨 Test PayPal Phishing` | `🏢 Test CEO Wire Fraud`
- `📅 Test Safe Google Invite` | `🔍 Test Typosquatting`
- `📊 View SOC Dashboard` | `📋 Capabilities & Tools`

### Forensics Report Card:
Upon analyzing an email, MailSentry renders:
- Threat Level Badge (🔴 CRITICAL PHISHING / 🟢 SAFE)
- Sender, Domain, Originating IP, and Authentication indicators
- Action Buttons:
  - `[🛡️ Quarantine & Block Sender]` (Primary Green Button)
  - `[📋 Export IOCs to SOC]`
  - `[🔄 Scan Another Email]`
  - `[📊 Open SOC Console]`

### Automated Containment Action:
When the user taps `[🛡️ Quarantine & Block Sender]`, the card delivers a selection callback to `agent.py`. The agent immediately triggers perimeter containment, creates Incident Ticket `#SEC-XXXX`, logs the block in `mailsentry.db`, and confirms resolution to the user in chat.

---

## 🌐 6. Agent Identity & Network Details

* **Agent Name**: `MailSentry AI`
* **Agent Address**: `agent1qvymlm8pvvm7rgx254mfhfuspnzyzklwx2rfw3cua2p0aztn46ew563kdc6`
* **Seed Phrase**: `mailsentry-ai-autonomous-security-sentinel-2026`
* **Network**: Fetch.ai Mainnet / Agentverse Mailbox
* **Protocol**: Agent Chat Protocol (`AgentChatProtocol 0.3.0` registered on Almanac)
* **Discoverable on**: [ASI:One](https://asi1.ai/)

---

## 🖥️ 7. Enterprise SOC Web Console

For security operations teams requiring centralized visibility, MailSentry includes an enterprise console running on FastAPI:
- **Port**: `http://localhost:8050`
- **Design**: Minimalist Linear/Vercel pure dark mode (`#000000` base, subtle borders, zero distracting neon glow).
- **Features**: Live Threat Score Gauge, MITRE ATT&CK badges, Decomposed Links Table, Search & Filter by sender/level, CSV export, and print-ready PDF incident dossiers.

---

## 🚀 8. Quickstart & Testing

### 1. Prerequisites
- Python 3.10, 3.11, or 3.12
- macOS, Linux, or Windows WSL

### 2. Setup Virtual Environment
```bash
git clone https://github.com/swameshawasthi-ctrl/mailsentry-ai.git
cd mailsentry-ai

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 3. Configure Environment (.env)
```env
AGENT_SEED="mailsentry-ai-autonomous-security-sentinel-2026"
AGENTVERSE_KEY="your-agentverse-api-key"
ASI1_API_KEY="your-asi1-api-key"
OPENAI_BASE_URL="https://api.asi1.ai/v1"
LLM_MODEL="asi1-mini"
```

### 4. Run the Agent & SOC Dashboard
```bash
# Terminal 1: Run MailSentry uAgent (connects to Agentverse Mailbox & ASI:One)
python agent.py

# Terminal 2: Run Enterprise SOC Console
python server.py
# Open http://localhost:8050 in your browser
```

### 5. Run Offline Automated Test Suite
```bash
python test_investigation.py
```

---

## 🧪 9. Sample Test Scenarios for Judges

### Scenario 1: PayPal Credential Harvesting (Critical Phishing)
```text
From: PayPal Support <security@paypa1-support.com>
Subject: URGENT: Your PayPal account has been suspended!
Date: Sat, 24 Oct 2026 10:15:00 +0000
Received: from mail-relay.paypa1-support.com (198.51.100.23)

Dear Customer,
We detected unauthorized logins from an unknown device. Your account will be permanently terminated in 30 minutes unless you verify your identity immediately.

Click here to verify your account and credit card details:
https://paypa1-support.com/auth/login-secure

Sincerely,
PayPal Security Team
```
*Expected Result*: Score 94/100, CRITICAL PHISHING, Typosquatting detected (`paypa1` vs `paypal`), Missing MX records, MITRE `T1566`.

### Scenario 2: Legitimate Google Calendar Invite (Safe)
```text
From: Google Calendar <notifications@calendar.google.com>
Subject: Invitation: Product Architecture Sync @ Mon Oct 26, 2026 2pm - 3pm (IST)
Date: Sat, 24 Oct 2026 08:00:00 +0000
Received: from mail-sor-f65.google.com (209.85.220.65)

You have been invited to the following event:
Product Architecture Sync
When: Monday, Oct 26, 2026 2:00 PM - 3:00 PM India Standard Time
Joining Info: Join with Google Meet: https://meet.google.com/abc-defg-hij
Organizer: engineering-team@fetch.ai
```
*Expected Result*: Score 15/100, SAFE / CLEAN, Authentic baseline signals.

---

## 📜 License & Compliance
Built under Apache 2.0 license for the Fetch-A-Thon 3.0 Hackathon.
All threat detection heuristics and indicators comply with standard STIX 2.1 and MITRE ATT&CK enterprise cyber frameworks.
