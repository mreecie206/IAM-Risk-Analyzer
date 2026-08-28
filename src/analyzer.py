# src/analyzer.py

from __future__ import annotations

import json
from typing import Any, Dict, List

from src.rules_engine import RulesEngine, RuleResult
from src.models import Finding, Severity
from src.reports import RiskReport


class Analyzer:
    """
    Central analyzer that runs the RulesEngine against IAM configuration
    and produces structured risk reports.
    """

    def __init__(self, rules_engine: RulesEngine | None = None) -> None:
        self.rules_engine = rules_engine or RulesEngine()

    def analyze(self, iam_config: Dict[str, Any]) -> RiskReport:
        """
        Run the rules engine against IAM config and return a RiskReport.
        """
        results: List[RuleResult] = self.rules_engine.evaluate(iam_config)

        all_findings: List[Finding] = []
        for result in results:
            all_findings.extend(result.findings)

        # Aggregate severity counts
        by_severity: Dict[Severity, int] = {}
        for f in all_findings:
            by_severity[f.severity] = by_severity.get(f.severity, 0) + 1

        # Aggregate NIST function counts
        by_nist: Dict[str, int] = {}
        for f in all_findings:
            by_nist[f.nist_function] = by_nist.get(f.nist_function, 0) + 1

        total_score = sum(f.score for f in all_findings)

        return RiskReport(
            total_score=round(total_score, 2),
            findings=all_findings,
            by_severity=by_severity,
            by_nist_function=by_nist,
        )

    def analyze_from_file(self, path: str) -> RiskReport:
        """
        Convenience method: load IAM config JSON from file and analyze.
        """
        with open(path, "r", encoding="utf-8") as f:
            iam_config = json.load(f)
        return self.analyze(iam_config)
