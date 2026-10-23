# 🛡️ MAILSENTRY AI — Autonomous Email Threat Investigation Agent

> **Built for FETCH-A-THON 3.0** | *ASI:One Agent Challenge: From Intent to Action*

[![Fetch.ai](https://img.shields.io/badge/Platform-Fetch.ai%20uAgents-blue?logo=fetch.ai)](https://fetch.ai)
[![ASI:One](https://img.shields.io/badge/Powered%20By-ASI%3AOne%20Agentverse-purple)](https://asi1.ai)
[![Protocol](https://img.shields.io/badge/Protocol-Agent%20Chat%20Protocol%20(ACP)-green)](https://agentverse.ai)
[![Python](https://img.shields.io/badge/Python-3.10%20%7C%203.11%20%7C%203.12-yellow)](https://python.org)

---

## 📌 Executive Summary

Phishing attacks and business email compromise (BEC) account for over 85% of corporate cyber breaches. Traditional spam filters provide binary flags (Spam vs. Inbox) without explaining *why* an email is dangerous or verifying deception indicators.

**MAILSENTRY AI** is an autonomous email cybersecurity investigation agent built on **Fetch.ai's uAgents framework** and native **Agent Chat Protocol (ACP)**. When a user pastes a suspicious email into **ASI:One**, MAILSENTRY AI does not merely reply with conversational advice; it actively executes a multi-tool forensic pipeline:

1. **Email & Header Parser**: Dissects sender headers, embedded links, and psychological intimidation triggers.
2. **Domain & DNS Forensics**: Detects typosquatting (e.g. `paypa1` vs `paypal`), high-abuse TLDs, and mail-exchange (MX) DNS anomalies.
3. **Phishing & Social Engineering Engine**: Analyzes urgency manipulation and credential harvesting cues.
4. **Weighted Risk Scoring & Mitigation**: Returns an executive forensic report with calculated risk score (0-100), evidence breakdown, and actionable next steps.

---

## 🏗️ Architecture: Intent to Action Workflow

```
       User in ASI:One Chat
                │
                │  "Analyze this suspicious email..."
                ▼
      ┌──────────────────┐
      │   ASI:One Chat   │
      └─────────┬────────┘
                │ Agent Chat Protocol (ACP)
                ▼
      ┌───────────────────────────────────────────────┐
      │     MAILSENTRY AI (uAgent on Agentverse)      │
      ├───────────────────────────────────────────────┤
      │                                               │
      │  ┌─────────────────┐    ┌──────────────────┐  │
      │  │  Email Parser   │ ──▶│  Domain Checker  │  │
      │  └─────────────────┘    └─────────┬────────┘  │
      │                                   │           │
      │  ┌─────────────────┐              ▼           │
      │  │ Risk Assessment │ ◀── ┌──────────────────┐ │
      │  │ & Scoring Engine│     │ Phishing Detector│ │
      │  └────────┬────────┘     └──────────────────┘ │
      │           │                                   │
      └───────────┼───────────────────────────────────┘
                  │
                  ▼
     Real-Time Threat Forensic Report
     (Risk Score, Evidence, Recommendations)
```

---

## 🚀 Quick Setup & Installation

### 1. Clone & Navigate
```bash
cd mailsentry-agent
```

### 2. Create Virtual Environment
```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Configure Environment Variables
Copy `.env.example` to `.env`:
```bash
cp .env.example .env
```
Fill in your credentials:
```env
AGENT_SEED="your-unique-secret-agent-seed-phrase"
AGENT_MAILBOX_KEY="your-mailbox-key-from-agentverse"
ASI1_API_KEY="your-asi1-api-key"
```

---

## 🧪 Testing the Forensics Pipeline Locally

Before connecting to the network, verify the intelligence pipeline on sample emails:

```bash
python test_investigation.py
```

Or pass any custom email snippet via CLI:
```bash
python agent.py --test "From: security@paypa1.com. Urgent: verify your password now."
```

---

## 🌐 Connecting to Agentverse & ASI:One

1. **Start the Agent**:
   ```bash
   python agent.py
   ```
2. **Mailbox Registration**:
   - The agent automatically connects via its Agentverse mailbox and registers with the Almanac API.
3. **Discover in ASI:One**:
   - Go to [ASI:One](https://asi1.ai).
   - Search for **MailSentry AI** (`agent1qvymlm8pvvm7rgx254mfhfuspnzyzklwx2rfw3cua2p0aztn46ew563kdc6`).
   - Send: *"Analyze this suspicious email: Your PayPal account has been suspended in 30 minutes! Verify at https://paypa1-support.com"*.

---

## 🖥️ Enterprise SOC Web Dashboard

In addition to autonomous chat on ASI:One, MailSentry AI includes a real-time Cybersecurity SOC Web Dashboard:

```bash
python server.py
```
Open **`http://localhost:8050`** in your browser to access:
- **Interactive Threat Scanner**: Paste suspicious email text or raw RFC headers.
- **Radial Threat Gauge**: Real-time risk meter (0–100) with visual severity states.
- **Live Incident Database**: SQLite persistence logging every scan from both ASI:One chat and web.
- **Export Forensic Reports**: One-click JSON incident export for corporate SOC analysts.

---

## ⚖️ Hackathon Judging Matrix Alignment

| Criteria | Weight | How MAILSENTRY AI Delivers |
| :--- | :---: | :--- |
| **Functionality** | 25% | Multi-tool forensic pipeline: RFC header parsing, SPF/DKIM validation, IP tracing, typosquatting & LLM reasoning. |
| **Fetch.ai Tech** | 20% | Implements native `uagents` 0.26, `AgentChatProtocol` 0.3.0, `Almanac` manifest & Agentverse Mailbox. |
| **Innovation** | 20% | Autonomous intent-to-action transition from passive spam filters to interactive cybersecurity agent. |
| **Real-World Impact** | 20% | Solves the #1 enterprise threat vector responsible for 85% of corporate cyber breaches. |
| **User Experience** | 15% | Dual UX: Instant conversational reports in ASI:One + sleek dark-mode SOC web dashboard. |

---

## 📜 License
MIT License — Created for Fetch-A-Thon 3.0.

