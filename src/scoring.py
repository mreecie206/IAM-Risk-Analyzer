from typing import List
from .rules_engine import RiskFinding

# Weighted scoring model for V1
SEVERITY_WEIGHTS = {
    "Critical": 40,
    "High": 25,
    "Medium": 10,
    "Low": 5
}


def compute_risk_score(findings: List[RiskFinding]) -> int:
    """
    Computes a numeric risk score (0–100) based on severity-weighted findings.
    """
    score = 0

    for f in findings:
        score += SEVERITY_WEIGHTS.get(f.severity, 0)

    # Clamp score between 0 and 100
    return max(0, min(score, 100))


def categorize_risk(score: int) -> str:
    """
    Converts numeric score into a risk category.
    """
    if score <= 30:
        return "Low"
    elif score <= 60:
        return "Medium"
    else:
        return "High"

