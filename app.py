import os
from typing import List, Optional

from fastapi import FastAPI, Depends, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import APIKeyHeader

from utils.api_response import success_response, error_response

# -----------------------------------------------------------------------------
# App initialization
# -----------------------------------------------------------------------------

app = FastAPI(
    title="Phishing Detection API",
    version="1.0.0",
    description="API for phishing and malicious URL detection"
)

# -----------------------------------------------------------------------------
# Environment
# -----------------------------------------------------------------------------

API_KEY = os.getenv("API_KEY")

if not API_KEY:
    raise RuntimeError("API_KEY environment variable is required")

# -----------------------------------------------------------------------------
# CORS (temporary – will harden in Step 4)
# -----------------------------------------------------------------------------

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -----------------------------------------------------------------------------
# Auth (HARDENED)
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

    # Accept both: "Bearer <key>" and "<key>"
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
# Scan endpoint
# -----------------------------------------------------------------------------

@app.post("/scan")
def scan_url(
    url: str,
    _: bool = Depends(authenticate)
):
    try:
        if not url:
            return error_response("URL is required", 400)

        result = {
            "url": url,
            "phishing": False,
            "confidence": 0.12
        }

        return success_response(result)

    except HTTPException as e:
        return error_response(e.detail, e.status_code)

    except Exception:
        return error_response("Scan failed", 500)

# -----------------------------------------------------------------------------
# Batch scan
# -----------------------------------------------------------------------------

@app.post("/scan_batch")
def scan_batch(
    urls: List[str],
    _: bool = Depends(authenticate)
):
    try:
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

    except HTTPException as e:
        return error_response(e.detail, e.status_code)

    except Exception:
        return error_response("Batch scan failed", 500)
