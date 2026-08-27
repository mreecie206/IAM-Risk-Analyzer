from typing import Dict

from .models import IdentityConfig
from .rules_engine import evaluate_risks
from .scoring import compute_risk_score, categorize_risk
from .reports import (
    generate_executive_summary,
    generate_technical_report,
    generate_top_risks,
)


def run_identity_risk_analyzer(config: IdentityConfig) -> Dict[str, object]:
    """
    Main entry point for the Identity Risk Analyzer.

    Takes an IdentityConfig, evaluates risks, computes a score,
    and returns structured outputs for use in CLI/UI.
    """

    # 1. Evaluate deterministic IAM risk rules
    findings = evaluate_risks(config)

    # 2. Compute numeric risk score
    score = compute_risk_score(findings)
    category = categorize_risk(score)

    # 3. Generate reports
    executive_summary = generate_executive_summary(score, findings)
    technical_report = generate_technical_report(findings)
    top_risks = generate_top_risks(findings)

    # 4. Return a structured result object
    return {
        "risk_score": score,
        "risk_category": category,
        "findings": findings,
        "top_risks": top_risks,
        "executive_summary": executive_summary,
        "technical_report": technical_report,
    }


