def calculate_risk(
    url_results,
    text_findings,
    malware_hits,
    text_ml_score: float
):
    explainability = []

    url_risk = sum(1 for u in url_results if u["risk"] == "high")
    heuristic_text_risk = len(text_findings)
    malware_risk = 1 if malware_hits else 0

    # --- Deterministic weighted ensemble ---
    score = (
        0.35 * min(url_risk, 1) * 100 +
        0.35 * text_ml_score * 100 +
        0.20 * malware_risk * 100 +
        0.10 * min(heuristic_text_risk, 3) * 10
    )

    score = int(min(score, 100))

    if url_risk:
        explainability.append("Suspicious URL detected")

    if text_ml_score > 0.7:
        explainability.append("ML model detected phishing language")

    if heuristic_text_risk:
        explainability.append("Suspicious email language detected")

    if malware_risk:
        explainability.append("Malware detected in attachment")

    verdict = (
        "SAFE" if score < 30 else
        "SUSPICIOUS" if score < 70 else
        "MALICIOUS"
    )

    return {
        "risk_score": score,
        "phishing_probability": round(score / 100, 2),
        "verdict": verdict,
        "explainability": list(set(explainability))
    }
