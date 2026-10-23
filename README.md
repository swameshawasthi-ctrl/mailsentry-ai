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
   - Open your [Agentverse Console](https://agentverse.ai).
   - Go to **Local Agents** / **Mailroom**.
   - Create a Mailbox, copy the Mailbox Key, and paste it into `.env` as `AGENT_MAILBOX_KEY`.
3. **Discover in ASI:One**:
   - Go to [ASI:One](https://asi1.ai).
   - Search for **MailSentry AI** by name or your Agent Address.
   - Send: *"Analyze this suspicious email: Your bank account will be closed in 1 hour. Verify at http://fakebank-support.xyz"*.

---

## ⚖️ Hackathon Judging Matrix Alignment

| Criteria | Weight | How MAILSENTRY AI Delivers |
| :--- | :---: | :--- |
| **Functionality** | 25% | Full multi-tool pipeline: parsing, DNS checks, typosquatting heuristic & LLM forensics. |
| **Fetch.ai Tech** | 20% | Implements native `uagents`, `AgentChatProtocol`, `Almanac` manifest & Agentverse Mailbox. |
| **Innovation** | 20% | Moves from static spam filters to autonomous interactive email threat forensics. |
| **Real-World Impact** | 20% | Directly targets the #1 vector of cybercrime & corporate financial fraud. |
| **User Experience** | 15% | Instant, clean, evidence-backed security reports delivered right inside ASI:One. |

---

## 📜 License
MIT License — Created for Fetch-A-Thon 3.0.
