import os
from typing import List, Optional

import requests
from fastapi import FastAPI, Depends, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import APIKeyHeader
from pydantic import BaseModel

from utils.api_response import success_response, error_response
from scanner.url_analyzer import analyze_urls
from scanner.email_analyzer import analyze_email_text as analyze_email_text_heuristics
from scanner.attachment_scanner import scan_attachments
from scanner.risk_engine import calculate_risk

# -----------------------------------------------------------------------------
# App initialization
# -----------------------------------------------------------------------------

app = FastAPI(
    title="PhishGuard Email Security API",
    version="1.1.0",
    description="API for phishing, malware, and email threat detection"
)

# -----------------------------------------------------------------------------
# Environment
# -----------------------------------------------------------------------------

API_KEY = os.getenv("API_KEY")
NLP_SERVICE_URL = os.getenv("NLP_SERVICE_URL", "http://localhost:8001/analyze/text")

if not API_KEY:
    raise RuntimeError("API_KEY environment variable is required")

# -----------------------------------------------------------------------------
# CORS (temporary – tighten later)
# -----------------------------------------------------------------------------

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -----------------------------------------------------------------------------
# Auth
# -----------------------------------------------------------------------------

api_key_header = APIKeyHeader(
    name="Authorization",
    auto_error=False,
    description="API key via Authorization header. Supports 'Bearer <key>' or raw key."
)


def authenticate(api_key: Optional[str] = Depends(api_key_header)):
    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing API key"
        )

    if api_key.lower().startswith("bearer "):
        api_key = api_key.split(" ", 1)[1].strip()

    if api_key != API_KEY:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid API key"
        )

    return True

# -----------------------------------------------------------------------------
# Global exception handler
# -----------------------------------------------------------------------------

@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    return error_response(
        message="Internal server error",
        status_code=500
    )

# -----------------------------------------------------------------------------
# Health
# -----------------------------------------------------------------------------

@app.get("/health")
def health_check():
    return success_response({"status": "ok"})

# -----------------------------------------------------------------------------
# Legacy URL scan (kept for compatibility)
# -----------------------------------------------------------------------------

@app.post("/scan")
def scan_url(
    url: str,
    _: bool = Depends(authenticate)
):
    if not url:
        return error_response("URL is required", 400)

    result = {
        "url": url,
        "phishing": False,
        "confidence": 0.12
    }

    return success_response(result)

# -----------------------------------------------------------------------------
# Legacy batch scan (kept for compatibility)
# -----------------------------------------------------------------------------

@app.post("/scan_batch")
def scan_batch(
    urls: List[str],
    _: bool = Depends(authenticate)
):
    if not urls:
        return error_response("URL list cannot be empty", 400)

    results = [
        {
            "url": url,
            "phishing": False,
            "confidence": 0.10
        }
        for url in urls
    ]

    return success_response(results)

# -----------------------------------------------------------------------------
# Email scan schemas
# -----------------------------------------------------------------------------

class Attachment(BaseModel):
    filename: str
    base64: str


class EmailScanRequest(BaseModel):
    subject: str
    sender: str
    body: str
    urls: List[str] = []
    attachments: List[Attachment] = []

# -----------------------------------------------------------------------------
# NLP ML Client (safe call)
# -----------------------------------------------------------------------------

def call_nlp_service(subject: str, body: str):
    try:
        resp = requests.post(
            NLP_SERVICE_URL,
            json={"subject": subject, "body": body},
            timeout=3
        )
        resp.raise_for_status()
        return resp.json()
    except Exception:
        # Fail-safe: neutral score if NLP is unavailable
        return {
            "text_ml_score": 0.0,
            "signals": [],
            "model_version": "nlp-unavailable"
        }

# -----------------------------------------------------------------------------
# Email scan (ENTERPRISE CORE ENDPOINT)
# -----------------------------------------------------------------------------

@app.post("/scan/email")
def scan_email(
    payload: EmailScanRequest,
    _: bool = Depends(authenticate)
):
    # URL heuristic analysis
    url_results = analyze_urls(payload.urls)

    # Heuristic text analysis
    heuristic_text_findings = analyze_email_text_heuristics(
        payload.subject,
        payload.body
    )

    # NLP ML analysis
    nlp_result = call_nlp_service(
        payload.subject,
        payload.body
    )

    text_ml_score = nlp_result.get("text_ml_score", 0.0)

    # Attachment malware scanning (ClamAV)
    malware_hits = scan_attachments(payload.attachments)

    # Final deterministic risk calculation
    risk = calculate_risk(
        url_results=url_results,
        text_findings=heuristic_text_findings,
        malware_hits=malware_hits,
        text_ml_score=text_ml_score
    )

    return success_response({
        **risk,
        "nlp_analysis": nlp_result,
        "url_analysis": url_results,
        "malware_analysis": {
            "detected": bool(malware_hits),
            "engine": "clamav",
            "details": malware_hits
        }
    })
