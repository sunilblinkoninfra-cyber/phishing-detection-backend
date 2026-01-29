from app.models.decision import EmailCategory, Decision

def calculate_risk(nlp_result, url_result, attach_result, rep_result, policy):
    risk = (
        nlp_result["score"]   * policy.weights["nlp"] +
        url_result["score"]   * policy.weights["url"] +
        attach_result["score"]* policy.weights["attachment"] +
        rep_result["score"]   * policy.weights["reputation"]
    )

    findings = {
        "nlp": nlp_result,
        "urls": url_result,
        "attachments": attach_result,
        "reputation": rep_result
    }

    return int(risk), findings
