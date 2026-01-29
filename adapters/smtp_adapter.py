import requests

BACKEND_URL = "https://<your-backend>/enforce/smtp"
API_KEY = "Bearer <API_KEY>"

def enforce_smtp_email(payload: dict):
    """
    Called by Postfix / MTA policy daemon
    """

    r = requests.post(
        BACKEND_URL,
        json=payload,
        headers={"Authorization": API_KEY},
        timeout=3
    )
    r.raise_for_status()
    return r.json()
