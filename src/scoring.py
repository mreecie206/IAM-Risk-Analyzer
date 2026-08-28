# src/scoring.py

from __future__ import annotations

from src.models import Finding


def calculate_risk_score(finding: Finding) -> float:
    """
    Calculate a risk score for a Finding.
    Default model: likelihood × impact × 100.
    """
    score = finding.likelihood * finding.impact * 100
    return round(score, 2)


def normalize_score(score: float, max_score: float = 100.0) -> float:
    """
    Normalize a score to a 0–1 scale.
    Useful if you want relative weighting across findings.
    """
    return min(score / max_score, 1.0)


def aggregate_scores(findings: list[Finding]) -> float:
    """
    Aggregate scores across findings.
    Currently: simple sum, but you could replace with weighted average.
    """
    return round(sum(f.score for f in findings), 2)
