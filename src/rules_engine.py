# src/rules_engine.py

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Protocol, Optional


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class Finding:
    id: str
    title: str
    description: str
    resource_id: Optional[str]
    severity: Severity
    nist_function: str  # e.g., IDENTIFY, PROTECT, DETECT, RESPOND, RECOVER
    likelihood: float   # 0.0–1.0
    impact: float       # 0.0–1.0
    score: float = field(init=False)

    def __post_init__(self) -> None:
        # Simple NIST-style risk score: likelihood × impact × 100
        self.score = round(self.likelihood * self.impact * 100, 2)


@dataclass
class RiskSummary:
    total_score: float
    findings: List[Finding]
    by_severity: Dict[Severity, int]
    by_nist_function: Dict[str, int]


class Rule(Protocol):
    """
    Base protocol for all rules.

    Each rule receives the full IAM configuration (already parsed)
    and returns a list of Findings.
    """

    id: str
    name: str
    description: str

    def evaluate(self, iam_config: Dict[str, Any]) -> List[Finding]:
        ...


class AdminWithoutMfaRule:
    id = "IAM-001"
    name = "Admin accounts without MFA"
    description = "Detects IAM users with administrative privileges that do not have MFA enabled."

    def evaluate(self, iam_config: Dict[str, Any]) -> List[Finding]:
        findings: List[Finding] = []

        users = iam_config.get("users", [])
        for user in users:
            # Expected structure (you can adapt to your actual schema):
            # {
            #   "user_id": str,
            #   "is_admin": bool,
            #   "mfa_enabled": bool
            # }
            if not user.get("is_admin"):
                continue

            if user.get("mfa_enabled"):
                continue

            findings.append(
                Finding(
                    id=self.id,
                    title=self.name,
                    description=(
                        f"Admin user '{user.get('user_id')}' does not have MFA enabled. "
                        "This significantly increases the risk of account compromise."
                    ),
                    resource_id=user.get("user_id"),
                    severity=Severity.CRITICAL,
                    nist_function="PROTECT",
                    likelihood=0.9,
                    impact=0.9,
                )
            )

        return findings


class StaleAccessKeysRule:
    id = "IAM-002"
    name = "Stale access keys"
    description = "Detects IAM access keys that have not been rotated within a defined threshold."

    def __init__(self, max_age_days: int = 90) -> None:
        self.max_age_days = max_age_days

    def evaluate(self, iam_config: Dict[str, Any]) -> List[Finding]:
        findings: List[Finding] = []

        keys = iam_config.get("access_keys", [])
        for key in keys:
            # Expected structure:
            # {
            #   "key_id": str,
            #   "user_id": str,
            #   "age_days": int,
            #   "active": bool
            # }
            if not key.get("active"):
                continue

            age_days = key.get("age_days", 0)
            if age_days <= self.max_age_days:
                continue

            severity = Severity.HIGH if age_days <= self.max_age_days * 2 else Severity.CRITICAL
            likelihood = 0.7 if severity == Severity.HIGH else 0.85
            impact = 0.7

            findings.append(
                Finding(
                    id=self.id,
                    title=self.name,
                    description=(
                        f"Access key '{key.get('key_id')}' for user '{key.get('user_id')}' "
                        f"is {age_days} days old, exceeding the rotation threshold
