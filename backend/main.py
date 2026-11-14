import os
import sys
from typing import Optional, List, Dict, Any
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

# Ensure current directory is in sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from database import init_db, add_or_update_flag, get_intel_for_indicators, get_trending_threats
from upi_sms_scanner import scan_message
from ai_persona import analyze_scam_persona

app = FastAPI(
    title="PhishGuard India API",
    description="AI-Powered Phishing & Regional UPI/SMS Scam Analyzer with Crowdsourced Threat Intelligence",
    version="1.0.0"
)

# CORS middleware for open accessibility
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

FRONTEND_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "frontend",
    "index.html"
)


# Initialize Database
@app.on_event("startup")
def startup_event():
    init_db()


# Pydantic Schemas
class AnalyzeRequest(BaseModel):
    message: Optional[str] = Field(default="", description="Raw message, SMS, email, or URL text to analyze")
    sender: Optional[str] = Field(default=None, description="Optional sender header or phone number (e.g. AD-HDFCBK, +919876543210)")


class FlagRequest(BaseModel):
    indicator_type: str = Field(..., description="Indicator type: 'msg_hash', 'upi_id', or 'url'")
    indicator_value: str = Field(default="", description="Indicator value")
    scam_category: str = Field(
        default="General Phishing / Scam",
        description="Category: 'Fake Bank / KYC Scam', 'UPI Collect / Refund Fraud', 'Digital Arrest / TRAI Scam', 'Electricity / e-Challan Scam', 'Job / Lottery Scam', or 'False Positive (Safe)'"
    )
    is_safe: bool = Field(default=False, description="True if community user is voting this as a safe false positive")


@app.get("/")
def serve_dashboard():
    """Serves the single self-contained dark-mode SOC dashboard directly."""
    if os.path.exists(FRONTEND_PATH):
        return FileResponse(FRONTEND_PATH, media_type="text/html")
    raise HTTPException(status_code=404, detail="Dashboard frontend not found.")


@app.post("/analyze")
def analyze_threat(payload: AnalyzeRequest):
    """
    Analyzes message through:
    1. Regional Indian regex and privacy SHA-256 fingerprinting
    2. Crowdsourced threat intelligence lookups in threats.db
    3. AI Scam Persona reverse-engineering (Ollama llama3.2 with heuristic fallback)
    """
    raw_msg = (payload.message or "").strip()
    message = raw_msg if raw_msg else "General inquiry / unpopulated payload"
    sender = payload.sender.strip() if payload.sender and payload.sender.strip() else None

    # Step 1: Regional Rule & Heuristic Scanner
    scan_res = scan_message(message, sender)

    # Step 2: Query Crowdsourced Threat Database
    indicators_to_check = [{"type": "msg_hash", "value": scan_res["msg_hash"]}]

    for upi in scan_res["upi"]["upi_ids"]:
        indicators_to_check.append({"type": "upi_id", "value": upi})

    for url in scan_res["urls"]["urls"]:
        indicators_to_check.append({"type": "url", "value": url})

    matched_intel = get_intel_for_indicators(indicators_to_check)

    total_flags = sum(item.get("flag_count", 0) for item in matched_intel)
    total_safe = sum(item.get("safe_votes", 0) for item in matched_intel)

    reported_categories = list(set(
        item.get("scam_category") for item in matched_intel if item.get("scam_category") and item.get("scam_category") != "False Positive (Safe)"
    ))

    # Step 3: Combine Rule Score with Community Intelligence
    raw_score = scan_res["base_score"]

    if total_flags > 0:
        boost = min(30, total_flags * 5)
        raw_score += boost

    if total_safe > 0 and total_safe > total_flags:
        reduction = min(35, (total_safe - total_flags) * 8)
        raw_score = max(5, raw_score - reduction)

    final_score = max(3, min(99, raw_score))

    # Determine Verdict
    if final_score >= 80:
        verdict = "CRITICAL THREAT"
        risk_level = "CRITICAL"
    elif final_score >= 50:
        verdict = "HIGH RISK SCAM"
        risk_level = "HIGH"
    elif final_score >= 25:
        verdict = "SUSPICIOUS ACTIVITY"
        risk_level = "SUSPICIOUS"
    else:
        verdict = "SAFE / LOW RISK"
        risk_level = "SAFE"

    # Step 4: AI Persona Reverse-Engineering
    persona = analyze_scam_persona(message, scan_res)

    # Compile flaggable indicators list for easy frontend voting
    flaggable = [{"type": "msg_hash", "value": scan_res["msg_hash"], "label": f"Message Fingerprint ({scan_res['msg_hash']})"}]
    for u in scan_res["upi"]["upi_ids"]:
        flaggable.append({"type": "upi_id", "value": u, "label": f"UPI VPA: {u}"})
    for link in scan_res["urls"]["urls"]:
        flaggable.append({"type": "url", "value": link, "label": f"URL: {link}"})

    return {
        "verdict": verdict,
        "risk_score": final_score,
        "risk_level": risk_level,
        "primary_category": reported_categories[0] if reported_categories else scan_res["primary_category"],
        "msg_hash": scan_res["msg_hash"],
        "scanner_details": scan_res,
        "community_intel": {
            "has_prior_reports": total_flags > 0,
            "total_flags": total_flags,
            "total_safe_votes": total_safe,
            "matched_indicators": matched_intel,
            "community_categories": reported_categories
        },
        "ai_persona": persona,
        "flaggable_indicators": flaggable
    }


@app.post("/flag")
def flag_threat(payload: FlagRequest):
    """
    Submits user crowdsourced threat confirmation or votes safe (False Positive).
    """
    valid_types = {"msg_hash", "upi_id", "url"}
    if payload.indicator_type not in valid_types:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid indicator_type '{payload.indicator_type}'. Must be one of {valid_types}"
        )

    updated = add_or_update_flag(
        indicator_type=payload.indicator_type,
        indicator_value=payload.indicator_value,
        scam_category=payload.scam_category,
        is_safe=payload.is_safe
    )

    return {
        "status": "success",
        "message": "Threat intelligence recorded successfully.",
        "record": updated
    }


@app.get("/trending")
def trending_threats():
    """
    Returns top 5 most-flagged threat indicators for the live sidebar feed.
    """
    trending = get_trending_threats(limit=5)
    return {
        "status": "success",
        "count": len(trending),
        "threats": trending
    }
