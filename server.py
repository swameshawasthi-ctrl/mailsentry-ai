import os
import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel
from dotenv import load_dotenv

load_dotenv()

from agent import run_investigation_pipeline
from database import get_recent_scans, get_summary_stats, init_db

# Ensure DB initialized
init_db()

app = FastAPI(title="MailSentry AI SOC Web Dashboard")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(BASE_DIR, "web", "static")
TEMPLATES_DIR = os.path.join(BASE_DIR, "web", "templates")

# Mount Static Assets
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

class AnalyzeRequest(BaseModel):
    raw_text: str
    source: str = "web_dashboard"

@app.get("/")
async def serve_index():
    index_path = os.path.join(TEMPLATES_DIR, "index.html")
    if not os.path.exists(index_path):
        raise HTTPException(status_code=404, detail="Template not found")
    return FileResponse(index_path)

@app.post("/api/analyze")
async def analyze_email(req: AnalyzeRequest):
    if not req.raw_text or not req.raw_text.strip():
        raise HTTPException(status_code=400, detail="Empty email content provided")

    # Run investigation pipeline (which also saves to database)
    assessment = run_investigation_pipeline(req.raw_text, source=req.source)

    from tools.email_parser import parse_email_content
    parsed = parse_email_content(req.raw_text)

    return JSONResponse({
        "threat_level": assessment.threat_level,
        "risk_score": assessment.risk_score,
        "attack_category": assessment.attack_category,
        "sender_email": parsed.sender_email,
        "sender_domain": parsed.sender_domain,
        "subject": parsed.subject,
        "evidence": assessment.evidence_items,
        "recommendations": assessment.actionable_recommendations,
        "analyst_reasoning": assessment.summary,
        "originating_ip": assessment.originating_ip,
        "ip_country": assessment.ip_country,
        "formatted_markdown": assessment.formatted_chat_report
    })

@app.get("/api/scans")
async def list_scans(limit: int = 25):
    return JSONResponse(get_recent_scans(limit=limit))

@app.get("/api/stats")
async def get_stats():
    return JSONResponse(get_summary_stats())

@app.get("/api/health")
async def health_check():
    return JSONResponse({
        "status": "healthy",
        "service": "MailSentry AI Threat Operations Server",
        "agentverse_mailbox": "active",
        "db": "connected"
    })

if __name__ == "__main__":
    port = int(os.getenv("PORT", 8050))
    print(f"[*] Starting MailSentry AI SOC Web Dashboard on http://localhost:{port}")
    uvicorn.run("server:app", host="0.0.0.0", port=port, reload=False)
