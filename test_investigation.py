"""
Verification test script for MailSentry AI Threat Intelligence Pipeline.
Runs multi-scenario test cases (Phishing, Typosquatting, Normal) to demonstrate
forensic accuracy without needing network calls.
"""
from agent import run_investigation_pipeline

SAMPLE_PHISHING_EMAIL = """
From: Security Sentinel <security@paypa1-support.com>
To: target.user@example.com
Subject: URGENT: Your PayPal Account Has Been Suspended in 30 minutes!

Dear Customer,

We detected unusual login attempts from an unknown device in Russia.
Your account will be permanently deactivated within 30 minutes unless you verify your identity.

Please confirm your password and billing info immediately at:
https://paypa1-support.com/verify-identity?token=928401

Failure to comply will lead to permanent forfeiture of your funds.

Sincerely,
PayPal Security Department
"""

SAMPLE_CLEAN_EMAIL = """
From: Team Calendar <notifications@calendar.google.com>
To: dev@company.com
Subject: Meeting Reminder: Sprint Planning at 3:00 PM

Hi Team,

This is a reminder for our scheduled Sprint Planning meeting today at 3:00 PM.
You can view the agenda on Google Meet:
https://meet.google.com/abc-defg-hij

Best,
Product Team
"""

def main():
    print("=" * 60)
    print("TEST SCENARIO 1: HIGH-RISK PHISHING & TYPOSQUATTING EMAIL")
    print("=" * 60)
    res1 = run_investigation_pipeline(SAMPLE_PHISHING_EMAIL)
    print(res1.formatted_chat_report)

    print("\n" + "=" * 60)
    print("TEST SCENARIO 2: LEGITIMATE WORKPLACE EMAIL")
    print("=" * 60)
    res2 = run_investigation_pipeline(SAMPLE_CLEAN_EMAIL)
    print(res2.formatted_chat_report)

if __name__ == "__main__":
    main()
