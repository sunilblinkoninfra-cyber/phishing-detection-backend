from app.services.parsers import parse_email
from app.services.nlp import analyze_intent
from app.services.urls import scan_urls
from app.services.attachments import scan_attachments
from app.services.reputation import check_reputation
from app.services.risk_engine import calculate_risk
from app.services.enforcement import enforce_decision

def process_email(raw_email: bytes, policy: object):
    parsed       = parse_email(raw_email)
    nlp_result   = analyze_intent(parsed)
    url_result   = scan_urls(parsed)
    attach_result= scan_attachments(parsed)
    rep_result   = check_reputation(parsed)

    risk_score, findings = calculate_risk(
        nlp_result,
        url_result,
        attach_result,
        rep_result,
        policy
    )

    category, decision = enforce_decision(risk_score)

    return {
        "email_id": parsed.message_id,
        "risk_score": risk_score,
        "category": category,
        "decision": decision,
        "findings": findings
    }
