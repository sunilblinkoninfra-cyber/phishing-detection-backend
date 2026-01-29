from app.models.decision import EmailCategory, Decision

def enforce_decision(risk_score: int):
    if risk_score > 75:
        return EmailCategory.HOT,  Decision.QUARANTINE
    if 40 < risk_score <= 75:
        return EmailCategory.WARM, Decision.ALLOW
    return EmailCategory.COLD, Decision.ALLOW
