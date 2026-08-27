from typing import List
from .rules_engine import RiskFinding
from .scoring import categorize_risk


def generate_executive_summary(score: int, findings: List[RiskFinding]) -> str:
    """
    Produces a concise executive-level summary of identity risk posture.
    """
    category = categorize_risk(score)
    top_titles = [f.title for f in findings[:3]] if findings else ["No risks detected"]

    summary = (
        f"Overall identity risk is {category} (score


