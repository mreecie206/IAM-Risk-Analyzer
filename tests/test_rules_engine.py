# tests/test_rules_engine.py

import pytest

from src.rules_engine import (
    RulesEngine,
    AdminWithoutMfaRule,
    StaleAccessKeysRule,
    OverlyPermissivePolicyRule,
)
from src.models import Severity


def test_admin_without_mfa_rule_triggers():
    config = {
        "users": [
            {"user_id": "alice", "is_admin": True, "mfa_enabled": False},
            {"user_id": "bob", "is_admin": True, "mfa_enabled": True},
        ]
    }
    rule = AdminWithoutMfaRule()
    findings = rule.evaluate(config)

    assert len(findings) == 1
    f = findings[0]
    assert f.resource_id == "alice"
    assert f.severity == Severity.CRITICAL
    assert f.score > 0


def test_stale_access_keys_rule_triggers():
    config = {
        "access_keys": [
            {"key_id": "AKIA123", "user_id": "alice", "age_days": 120, "active": True},
            {"key_id": "AKIA456", "user_id": "bob", "age_days": 30, "active": True},
        ]
    }
    rule = StaleAccessKeysRule(max_age_days=90)
    findings = rule.evaluate(config)

    assert len(findings) == 1
    f = findings[0]
    assert f.resource_id == "AKIA123"
    assert f.severity in (Severity.HIGH, Severity.CRITICAL)
    assert f.score > 0


def test_overly_permissive_policy_rule_triggers():
    config = {
        "policies": [
            {
                "policy_id": "AdminPolicy",
                "statements": [
                    {"effect": "Allow", "actions": ["*"], "resources": ["*"]}
                ],
            },
            {
                "policy_id": "SafePolicy",
                "statements": [
                    {
                        "effect": "Allow",
                        "actions": ["s3:GetObject"],
                        "resources": ["arn:aws:s3:::bucket/*"],
                    }
                ],
            },
        ]
    }
    rule = OverlyPermissivePolicyRule()
    findings = rule.evaluate(config)

    assert len(findings) == 1
    f = findings[0]
    assert f.resource_id == "AdminPolicy"
    assert f.severity == Severity.HIGH
    assert f.score > 0


def test_rules_engine_runs_all_rules():
    config = {
        "users": [{"user_id": "alice", "is_admin": True, "mfa_enabled": False}],
        "access_keys": [
            {"key_id": "AKIA123", "user_id": "alice", "age_days": 120, "active": True}
        ],
        "policies": [
            {
                "policy_id": "AdminPolicy",
                "statements": [
                    {"effect": "Allow", "actions": ["*"], "resources": ["*"]}
                ],
            }
        ],
    }

    engine = RulesEngine()
    results = engine.evaluate(config)

    # Ensure all three rules produced findings
    total_findings = sum(len(r.findings) for r in results)
    assert total_findings >= 3

