# src/rules_engine.py

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Protocol

from src.models import Finding, Severity
from src.scoring import calculate_risk_score


class Rule(Protocol):
    """
    Base interface for all rules.
    Every rule receives normalized IAM config and returns Findings.
    """

    id: str
    name: str
    description: str

    def evaluate(self, iam_config: Dict[str, Any]) -> List[Finding]:
        ...


@dataclass
class RuleResult:
    rule_id: str
    findings: List[Finding]


# ---------------------------------------------------------------------------
# RULE IMPLEMENTATIONS
# ---------------------------------------------------------------------------

class AdminWithoutMfaRule:
    id = "IAM-001"
    name = "Admin accounts without MFA"
    description = "Detects admin IAM users who do not have MFA enabled."

    def evaluate(self, iam_config: Dict[str, Any]) -> List[Finding]:
        findings: List[Finding] = []

        for user in iam_config.get("users", []):
            if not user.get("is_admin"):
                continue

            if user.get("mfa_enabled"):
                continue

            finding = Finding(
                id=self.id,
                title=self.name,
                description=(
                    f"Admin user '{user['user_id']}' does not have MFA enabled. "
                    "This significantly increases compromise risk."
                ),
                resource_id=user["user_id"],
                severity=Severity.CRITICAL,
                nist_function="PROTECT",
                likelihood=0.9,
                impact=0.9,
            )

            finding.score = calculate_risk_score(finding)
            findings.append(finding)

        return findings


class StaleAccessKeysRule:
    id = "IAM-002"
    name = "Stale access keys"
    description = "Detects IAM access keys older than rotation threshold."

    def __init__(self, max_age_days: int = 90):
        self.max_age_days = max_age_days

    def evaluate(self, iam_config: Dict[str, Any]) -> List[Finding]:
        findings: List[Finding] = []

        for key in iam_config.get("access_keys", []):
            if not key.get("active"):
                continue

            age = key.get("age_days", 0)
            if age <= self.max_age_days:
                continue

            severity = (
                Severity.HIGH if age <= self.max_age_days * 2 else Severity.CRITICAL
            )

            likelihood = 0.7 if severity == Severity.HIGH else 0.85
            impact = 0.7

            finding = Finding(
                id=self.id,
                title=self.name,
                description=(
                    f"Access key '{key['key_id']}' for user '{key['user_id']}' "
                    f"is {age} days old (threshold: {self.max_age_days})."
                ),
                resource_id=key["key_id"],
                severity=severity,
                nist_function="PROTECT",
                likelihood=likelihood,
                impact=impact,
            )

            finding.score = calculate_risk_score(finding)
            findings.append(finding)

        return findings


class OverlyPermissivePolicyRule:
    id = "IAM-003"
    name = "Overly permissive policies"
    description = "Detects IAM policies with wildcard permissions."

    def evaluate(self, iam_config: Dict[str, Any]) -> List[Finding]:
        findings: List[Finding] = []

        for policy in iam_config.get("policies", []):
            policy_id = policy.get("policy_id")

            for stmt in policy.get("statements", []):
                if stmt.get("effect") != "Allow":
                    continue

                actions = stmt.get("actions", [])
                resources = stmt.get("resources", [])

                wildcard_action = any(a == "*" or a.endswith(":*") for a in actions)
                wildcard_resource = any(r == "*" for r in resources)

                if not (wildcard_action or wildcard_resource):
                    continue

                finding = Finding(
                    id=self.id,
                    title=self.name,
                    description=(
                        f"Policy '{policy_id}' contains overly permissive statement "
                        f"actions={actions}, resources={resources}."
                    ),
                    resource_id=policy_id,
                    severity=Severity.HIGH,
                    nist_function="PROTECT",
                    likelihood=0.8,
                    impact=0.8,
                )

                finding.score = calculate_risk_score(finding)
                findings.append(finding)

        return findings


# ---------------------------------------------------------------------------
# RULES ENGINE
# ---------------------------------------------------------------------------

class RulesEngine:
    """
    Runs all rules against IAM config and returns structured results.
    """

    def __init__(self, rules: List[Rule] | None = None):
        self.rules = rules or [
            AdminWithoutMfaRule(),
            StaleAccessKeysRule(),
            OverlyPermissivePolicyRule(),
        ]

    def add_rule(self, rule: Rule) -> None:
        self.rules.append(rule)

    def evaluate(self, iam_config: Dict[str, Any]) -> List[RuleResult]:
        results: List[RuleResult] = []

        for rule in self.rules:
            try:
                findings = rule.evaluate(iam_config)
                results.append(
                    RuleResult(rule_id=rule.id, findings=findings)
                )
            except Exception as exc:
                print(f"[RulesEngine] Rule {rule.id} failed: {exc}")

        return results
