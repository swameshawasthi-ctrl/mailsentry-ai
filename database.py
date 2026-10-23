import sqlite3
import json
import os
from datetime import datetime
from typing import List, Dict, Any, Optional

DB_PATH = os.path.join(os.path.dirname(__file__), "mailsentry.db")

def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        created_at TEXT NOT NULL,
        sender_email TEXT,
        sender_domain TEXT,
        subject TEXT,
        risk_score INTEGER NOT NULL,
        threat_level TEXT NOT NULL,
        attack_category TEXT NOT NULL,
        evidence_json TEXT,
        recommendations_json TEXT,
        originating_ip TEXT,
        ip_country TEXT,
        raw_text TEXT,
        source TEXT DEFAULT 'asi1_chat'
    )
    """)
    conn.commit()
    conn.close()

def save_scan(
    sender_email: Optional[str],
    sender_domain: Optional[str],
    subject: Optional[str],
    risk_score: int,
    threat_level: str,
    attack_category: str,
    evidence: List[str],
    recommendations: List[str],
    originating_ip: Optional[str] = None,
    ip_country: Optional[str] = None,
    raw_text: str = "",
    source: str = "asi1_chat"
) -> int:
    conn = get_connection()
    cursor = conn.cursor()
    created_at = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    
    cursor.execute("""
        INSERT INTO scans (
            created_at, sender_email, sender_domain, subject,
            risk_score, threat_level, attack_category,
            evidence_json, recommendations_json,
            originating_ip, ip_country, raw_text, source
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        created_at,
        sender_email,
        sender_domain,
        subject,
        risk_score,
        threat_level,
        attack_category,
        json.dumps(evidence),
        json.dumps(recommendations),
        originating_ip,
        ip_country,
        raw_text,
        source
    ))
    scan_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return scan_id

def get_recent_scans(limit: int = 20) -> List[Dict[str, Any]]:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,))
    rows = cursor.fetchall()
    conn.close()

    results = []
    for r in rows:
        results.append({
            "id": r["id"],
            "created_at": r["created_at"],
            "sender_email": r["sender_email"],
            "sender_domain": r["sender_domain"],
            "subject": r["subject"],
            "risk_score": r["risk_score"],
            "threat_level": r["threat_level"],
            "attack_category": r["attack_category"],
            "evidence": json.loads(r["evidence_json"] or "[]"),
            "recommendations": json.loads(r["recommendations_json"] or "[]"),
            "originating_ip": r["originating_ip"],
            "ip_country": r["ip_country"],
            "source": r["source"],
            "raw_text_snippet": (r["raw_text"] or "")[:120]
        })
    return results

def get_summary_stats() -> Dict[str, Any]:
    conn = get_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT COUNT(*) as total FROM scans")
    total = cursor.fetchone()["total"]

    cursor.execute("SELECT COUNT(*) as critical FROM scans WHERE risk_score >= 80")
    critical = cursor.fetchone()["critical"]

    cursor.execute("SELECT COUNT(*) as safe FROM scans WHERE risk_score < 30")
    safe = cursor.fetchone()["safe"]

    cursor.execute("SELECT AVG(risk_score) as avg_score FROM scans")
    avg_score = cursor.fetchone()["avg_score"] or 0

    conn.close()

    return {
        "total_scans": total,
        "critical_threats": critical,
        "safe_emails": safe,
        "avg_risk_score": round(avg_score, 1),
        "threat_interception_rate": f"{round((critical / total * 100), 1)}%" if total > 0 else "0%"
    }

# Auto initialize database on module import
init_db()
