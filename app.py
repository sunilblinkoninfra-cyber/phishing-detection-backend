import os
import uuid
import json
from typing import List, Optional
from enum import Enum

import requests
from fastapi import FastAPI, Depends, HTTPException, Request, Body
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import APIKeyHeader
from fastapi import Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from db import get_db
from models.soc import (
    FalsePositiveRequest,
    ConfirmMaliciousRequest,
    ReleaseQuarantineRequest,
)

# Existing scanners (REUSED)
from scanner.email_analyzer import analyze_email_text as analyze_email_text_heuristics
from scanner.attachment_scanner import scan_attachments
from scanner.url_ml_v2 import analyze_urls
from scanner.risk_engine import calculate_risk

# --------------------------------------------------
# App init (Swagger disabled — backend authority)
# --------------------------------------------------

app = FastAPI(title="PhishGuardAI Backend", docs_url=None, redoc_url=None, openapi_url=None)

@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    print("UNHANDLED_EXCEPTION:", repr(exc))
    return JSONResponse(
        status_code=500,
        content={
            "status": "error",
            "message": "Internal server error"
        }
    )

# --------------------------------------------------
# Environment
# --------------------------------------------------

API_KEY = os.getenv("API_KEY")
NLP_SERVICE_URL = os.getenv("NLP_SERVICE_URL")

if not API_KEY:
    raise RuntimeError("API_KEY environment variable is required")

# --------------------------------------------------
# CORS
# --------------------------------------------------

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# --------------------------------------------------
# Auth
# --------------------------------------------------

api_key_header = APIKeyHeader(name="Authorization", auto_error=False)

def authenticate(api_key: Optional[str] = Depends(api_key_header)):
    if not api_key:
        raise HTTPException(status_code=401, detail="Missing API key")
    if api_key.lower().startswith("bearer "):
        api_key = api_key.split(" ", 1)[1].strip()
    if api_key != API_KEY:
        raise HTTPException(status_code=403, detail="Invalid API key")
    return True

# --------------------------------------------------
# Error handler
# --------------------------------------------------

@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    print("UNHANDLED_EXCEPTION:", repr(exc))
    return {"status": "error", "message": "Internal server error"}

# --------------------------------------------------
# Health
# --------------------------------------------------

@app.get("/health")
def health():
    return {"status": "ok"}

# --------------------------------------------------
# Core Models
# --------------------------------------------------

class EmailCategory(str, Enum):
    COLD = "COLD"
    WARM = "WARM"
    HOT = "HOT"

class Decision(str, Enum):
    ALLOW = "ALLOW"
    QUARANTINE = "QUARANTINE"

class Attachment(BaseModel):
    filename: str
    base64: str

class EmailScanRequest(BaseModel):
    subject: str
    sender: str
    body: str
    urls: List[str] = []
    attachments: List[Attachment] = []

class EmailDecisionResponse(BaseModel):
    email_id: str
    risk_score: int
    category: EmailCategory
    decision: Decision
    findings: dict

# --------------------------------------------------
# Tenant Context Resolution (PHASE 5)
# --------------------------------------------------

def get_tenant_id(request: Request) -> str:
    tenant_id = request.headers.get("X-Tenant-ID")
    if not tenant_id:
        raise HTTPException(status_code=400, detail="Missing X-Tenant-ID header")
    return tenant_id

# --------------------------------------------------
# Tenant Policy Resolution (PHASE 5)
# --------------------------------------------------

def get_active_policy(tenant_id: str):
    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
        SELECT cold_threshold, warm_threshold, weights
        FROM tenant_policies
        WHERE tenant_id = %s AND active = TRUE
        ORDER BY created_at DESC
        LIMIT 1
    """, (tenant_id,))

    row = cur.fetchone()
    cur.close()
    conn.close()

    if not row:
        return {
            "cold": 40,
            "warm": 75,
            "weights": {
                "nlp": 0.3,
                "url": 0.4,
                "attachment": 0.2,
                "reputation": 0.1
            }
        }

    return {
        "cold": row["cold_threshold"],
        "warm": row["warm_threshold"],
        "weights": row["weights"]
    }

# --------------------------------------------------
# Blocklist Enforcement (PHASE 5)
# --------------------------------------------------

def is_blocked(tenant_id: str, sender: str, urls: List[str]):
    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
        SELECT block_type, value
        FROM blocklists
        WHERE tenant_id = %s AND active = TRUE
    """, (tenant_id,))

    rows = cur.fetchall()
    cur.close()
    conn.close()

    sender_l = sender.lower()

    for r in rows:
        if r["block_type"] == "SENDER" and sender_l == r["value"].lower():
            return True, "SENDER_BLOCKED"
        if r["block_type"] == "DOMAIN" and sender_l.endswith(r["value"].lower()):
            return True, "DOMAIN_BLOCKED"
        if r["block_type"] == "URL":
            for u in urls:
                if r["value"] in u:
                    return True, "URL_BLOCKED"

    return False, None

# --------------------------------------------------
# Phase 6 Helper — Shared Enforcement Entry
# --------------------------------------------------

def evaluate_email_for_enforcement(
    tenant_id: str,
    subject: str,
    sender: str,
    body: str,
    urls: list
):
    """
    Shared enforcement entrypoint for SMTP / Graph.
    Calls the canonical ingest pipeline.
    """
    fake_request = Request(
        scope={
            "type": "http",
            "headers": [(b"x-tenant-id", tenant_id.encode())]
        }
    )

    decision = ingest_email(
        EmailScanRequest(
            subject=subject,
            sender=sender,
            body=body,
            urls=urls,
            attachments=[]
        ),
        fake_request
    )

    return decision

# --------------------------------------------------
# Role Enforcement (Phase 4)
# --------------------------------------------------

def require_soc_role(actor_role: str, allowed: List[str]):
    if actor_role not in allowed:
        raise HTTPException(status_code=403, detail="Insufficient SOC privileges")

# --------------------------------------------------
# SOC Action Helpers (IMMUTABLE)
# --------------------------------------------------

def call_nlp_service(subject: str, body: str) -> dict:
    """
    Safe NLP call. Never crashes the pipeline.
    """
    if not NLP_SERVICE_URL:
        return {
            "text_ml_score": 0.0,
            "model_version": "nlp_disabled"
        }

    try:
        resp = requests.post(
            NLP_SERVICE_URL,
            json={"subject": subject, "body": body},
            timeout=2
        )
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        print("NLP SERVICE ERROR:", repr(e))
        return {
            "text_ml_score": 0.0,
            "model_version": "nlp_error"
        }


def record_soc_action(alert_id: str, action: str, actor: dict, notes: Optional[str]):
    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
        INSERT INTO soc_actions (id, alert_id, action, acted_by, notes)
        VALUES (%s, %s, %s, %s, %s)
    """, (
        str(uuid.uuid4()),
        alert_id,
        action,
        json.dumps(actor),
        notes
    ))

    cur.execute("""
        INSERT INTO audit_log (id, entity_type, entity_id, action, actor)
        VALUES (%s, %s, %s, %s, %s)
    """, (
        str(uuid.uuid4()),
        "SOC_ALERT",
        alert_id,
        action,
        json.dumps(actor)
    ))

    conn.commit()
    cur.close()
    conn.close()

# --------------------------------------------------
# Persist decision + SOC alert
# --------------------------------------------------

def persist_decision(email_id, risk_score, category, decision, findings):
    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
        INSERT INTO email_decisions
        (id, risk_score, category, decision, findings, model_version)
        VALUES (%s, %s, %s, %s, %s, %s)
    """, (
        email_id,
        risk_score,
        category,
        decision,
        json.dumps(findings),
        findings.get("nlp", {}).get("model_version")
    ))

    if category in (EmailCategory.WARM, EmailCategory.HOT):
        cur.execute("""
            INSERT INTO soc_alerts (id, email_id, category)
            VALUES (%s, %s, %s)
        """, (
            str(uuid.uuid4()),
            email_id,
            category
        ))

    conn.commit()
    cur.close()
    conn.close()

# --------------------------------------------------
# Inline ingest endpoint (PHASE 5 AUTHORITATIVE)
# --------------------------------------------------

@app.post(
    "/ingest/email",
    response_model=EmailDecisionResponse,
    dependencies=[Depends(authenticate)]
)
def ingest_email(
    payload: EmailScanRequest = Body(...),
    request: Request = None
):
    tenant_id = get_tenant_id(request)
    email_id = str(uuid.uuid4())

    # 0️⃣ Blocklist hard stop
    blocked, reason = is_blocked(
        tenant_id,
        payload.sender,
        payload.urls or []
    )

    if blocked:
        findings = {"block_reason": reason}
        persist_decision(
            email_id,
            100,
            EmailCategory.HOT,
            Decision.QUARANTINE,
            findings
        )
        return EmailDecisionResponse(
            email_id=email_id,
            risk_score=100,
            category=EmailCategory.HOT,
            decision=Decision.QUARANTINE,
            findings=findings
        )

    # 1️⃣ Resolve tenant policy
    policy = get_active_policy(tenant_id)

    # 2️⃣ Analysis
    url_result = analyze_urls(payload.urls or [])
    text_heuristic = analyze_email_text_heuristics(payload.subject, payload.body)
    nlp_result = call_nlp_service(payload.subject, payload.body)

    try:
        malware_hits = scan_attachments(payload.attachments or [])
    except Exception:
        malware_hits = []

    # 3️⃣ Weighted risk
   risk_eval = calculate_risk(
    text_ml_score=nlp_result.get("text_ml_score", 0.0),
    text_findings=text_heuristic,
    url_result=url_result,
    malware_hits=malware_hits,
)

# 🔐 HARD GUARANTEE: risk_score is ALWAYS an int
risk_score = int(
    risk_eval["risk_score"]
    if isinstance(risk_eval, dict)
    else risk_eval
)

    # 4️⃣ Policy thresholds
    if risk_score >= policy["warm"]:
        category, decision = EmailCategory.HOT, Decision.QUARANTINE
    elif risk_score >= policy["cold"]:
        category, decision = EmailCategory.WARM, Decision.ALLOW
    else:
        category, decision = EmailCategory.COLD, Decision.ALLOW

    findings = {
        "policy": policy,
        "nlp": nlp_result,
        "urls": url_result,
        "email_text": text_heuristic,
        "malware": malware_hits
    }

    persist_decision(email_id, risk_score, category, decision, findings)

    return EmailDecisionResponse(
        email_id=email_id,
        risk_score=risk_score,
        category=category,
        decision=decision,
        findings=findings
    )

# --------------------------------------------------
# Phase 6 — SMTP Enforcement Endpoint
# --------------------------------------------------

@app.post("/enforce/smtp", dependencies=[Depends(authenticate)])
def smtp_enforcement(payload: dict):
    """
    Payload fields:
    - tenant_id
    - mail_from
    - subject
    - body
    - urls
    """

    decision = evaluate_email_for_enforcement(
        tenant_id=payload["tenant_id"],
        subject=payload.get("subject", ""),
        sender=payload["mail_from"],
        body=payload.get("body", ""),
        urls=payload.get("urls", [])
    )

    if decision.category == EmailCategory.HOT:
        return {"smtp_code": 550, "message": "Rejected by PhishGuardAI"}

    if decision.category == EmailCategory.WARM:
        return {"smtp_code": 250, "message": "Accepted with warning"}

    return {"smtp_code": 250, "message": "Accepted"}


# --------------------------------------------------
# SOC BLOCKLIST MANAGEMENT ENDPOINT (PHASE 5)
# --------------------------------------------------

@app.post("/soc/block", dependencies=[Depends(authenticate)])
def add_block(
    block_type: str,
    value: str,
    request: Request,
    actor: dict = Body(...)
):
    tenant_id = get_tenant_id(request)
    require_soc_role(actor.get("role"), ["SOC_ADMIN"])

    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
        INSERT INTO blocklists (id, tenant_id, block_type, value, created_by)
        VALUES (%s, %s, %s, %s, %s)
    """, (
        str(uuid.uuid4()),
        tenant_id,
        block_type,
        value,
        json.dumps(actor)
    ))

    conn.commit()
    cur.close()
    conn.close()

    return {"status": "blocked", "type": block_type, "value": value}

# --------------------------------------------------
# Phase 4 SOC endpoints remain unchanged
# --------------------------------------------------

@app.post("/soc/false-positive", dependencies=[Depends(authenticate)])
def mark_false_positive(payload: FalsePositiveRequest):
    require_soc_role(payload.acted_by.role, ["SOC_ANALYST", "SOC_ADMIN"])
    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
        UPDATE soc_alerts
        SET status = 'CLOSED'
        WHERE id = %s
    """, (payload.alert_id,))

    cur.execute("""
        INSERT INTO ml_feedback (id, email_id, label, source)
        SELECT %s, email_id, 'FP', 'SOC'
        FROM soc_alerts WHERE id = %s
    """, (
        str(uuid.uuid4()),
        payload.alert_id
    ))

    conn.commit()
    cur.close()
    conn.close()

    record_soc_action(
        payload.alert_id,
        "FALSE_POSITIVE",
        payload.acted_by.dict(),
        payload.notes
    )

    return {"status": "false_positive_recorded"}

@app.post("/soc/confirm-malicious", dependencies=[Depends(authenticate)])
def confirm_malicious(payload: ConfirmMaliciousRequest):
    require_soc_role(payload.acted_by.role, ["SOC_ANALYST", "SOC_ADMIN"])
    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
        UPDATE soc_alerts
        SET status = 'CONFIRMED_MALICIOUS'
        WHERE id = %s
    """, (payload.alert_id,))

    cur.execute("""
        INSERT INTO ml_feedback (id, email_id, label, source)
        SELECT %s, email_id, 'TP', 'SOC'
        FROM soc_alerts WHERE id = %s
    """, (
        str(uuid.uuid4()),
        payload.alert_id
    ))

    conn.commit()
    cur.close()
    conn.close()

    record_soc_action(
        payload.alert_id,
        "CONFIRM_MALICIOUS",
        payload.acted_by.dict(),
        payload.notes
    )

    return {"status": "malicious_confirmed"}

@app.post("/soc/release-quarantine", dependencies=[Depends(authenticate)])
def release_quarantine(payload: ReleaseQuarantineRequest):
    require_soc_role(payload.acted_by.role, ["SOC_ADMIN"])
    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
        UPDATE soc_alerts
        SET status = 'RELEASED'
        WHERE id = %s
    """, (payload.alert_id,))

    conn.commit()
    cur.close()
    conn.close()

    record_soc_action(
        payload.alert_id,
        "RELEASE_QUARANTINE",
        payload.acted_by.dict(),
        payload.notes
    )

    return {"status": "email_released"}

# --------------------------------------------------
# Phase 6 — Microsoft Graph Enforcement Endpoint
# --------------------------------------------------

@app.post("/enforce/graph", dependencies=[Depends(authenticate)])
def graph_enforcement(payload: dict):
    """
    Payload:
    - tenant_id
    - message_id
    - sender
    - subject
    - body
    """

    decision = evaluate_email_for_enforcement(
        tenant_id=payload["tenant_id"],
        subject=payload["subject"],
        sender=payload["sender"],
        body=payload["body"],
        urls=payload.get("urls", [])
    )

    if decision.category == EmailCategory.HOT:
        # Graph quarantine hook (token mgmt later)
        pass

    return {"status": "processed"}

# --------------------------------------------------
# Entrypoint
# --------------------------------------------------

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=int(os.getenv("PORT", 10000)))
