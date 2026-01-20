import requests
from typing import Dict

NLP_SERVICE_URL = "http://localhost:8001/analyze/text"
TIMEOUT_SECONDS = 3


def analyze_email_text(subject: str, body: str) -> Dict:
    """
    Calls the NLP phishing detection service.
    Fails safely if the service is unavailable.
    """
    try:
        response = requests.post(
            NLP_SERVICE_URL,
            json={
                "subject": subject,
                "body": body
            },
            timeout=TIMEOUT_SECONDS
        )
        response.raise_for_status()
        return response.json()
    except Exception:
        # Fail safe: return neutral score
        return {
            "text_ml_score": 0.0,
            "signals": [],
            "model_version": "nlp-unavailable"
        }
