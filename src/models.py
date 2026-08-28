# src/models.py

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Severity(str, Enum):
    """
    Severity levels for IAM risk findings.
    """
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class Finding:
    """
    Represents a single risk finding produced by a rule.
    """
    id: str
    title: str
    description: str
    resource_id: Optional[str]
    severity: Severity
    nist_function: str  # IDENTIFY, PROTECT, DETECT, RESPOND, RECOVER
    likelihood: float   # 0.0–1.0
    impact: float       # 0.0–1.0
    score: float = field(default=0.0)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "resource_id": self.resource_id,
            "severity": self.severity.value,
            "nist_function": self.nist_function,
            "likelihood": self.likelihood,
            "impact": self.impact,
            "score": self.score,
        }
