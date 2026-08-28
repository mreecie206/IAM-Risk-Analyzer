# src/reports.py

from __future__ import annotations

import json
from dataclasses import dataclass, asdict
from typing import Dict, List

from src.models import Finding, Severity


@dataclass
class RiskReport:
    """
    Structured risk report produced by Analyzer.
    """
    total_score: float
    findings: List[Finding]
    by_severity: Dict[Severity, int]
    by_nist_function: Dict[str, int]

    def to_dict(self) -> Dict:
        """
        Convert report to a plain dictionary for serialization.
        """
        return {
            "total_score": self.total_score,
            "findings": [asdict(f) for f in self.findings],
            "by_severity": {s.value: c for s, c in self.by_severity.items()},
            "by_nist_function": self.by_nist_function,
        }

    def to_json(self, indent: int = 2) -> str:
        """
        Serialize report to JSON string.
        """
        return json.dumps(self.to_dict(), indent=indent)

    def to_text(self) -> str:
        """
        Human-readable text summary for CLI output.
        """
        lines: List[str] = []
        lines.append("=== IAM Risk Report ===")
        lines.append(f"Total Risk Score: {self.total_score}")
        lines.append("")

        lines.append("By Severity:")
        for severity, count in self.by_severity.items():
            lines.append(f"  {severity.value}: {count}")

        lines.append("")
        lines.append("By NIST Function:")
        for fn, count in self.by_nist_function.items():
            lines.append(f"  {fn}: {count}")

        lines.append("")
        lines.append("Findings:")
        for f in self.findings:
            lines.append(
                f"- [{f.severity.value}] {f.title} "
                f"(Resource: {f.resource_id}, Score: {f.score})"
            )
            lines.append(f"    {f.description}")

        return "\n".join(lines)
