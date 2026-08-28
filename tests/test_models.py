# tests/test_models.py

import pytest
from src.models import Finding, Severity


def test_severity_enum_values():
    # Ensure enum contains expected values
    assert Severity.LOW.value == "LOW"
    assert Severity.MEDIUM.value == "MEDIUM"
    assert Severity.HIGH.value == "HIGH"
    assert Severity.CRITICAL.value == "CRITICAL"


def test_finding_creation_and_defaults():
    finding = Finding(
        id="TEST-001",
        title="Test Finding",
        description="This is a test finding.",
        resource_id="resource-123",
        severity=Severity.HIGH,
        nist_function="PROTECT",
        likelihood=0.8,
        impact=0.7,
    )

    # Ensure fields are set correctly
    assert finding.id == "TEST-001"
    assert finding.title == "Test Finding"
    assert finding.severity == Severity.HIGH
    assert finding.nist_function == "PROTECT"
    assert finding.score == 0.0  # default before scoring


def test_finding_to_dict_serialization():
    finding = Finding(
        id="TEST-002",
        title="Serialization Test",
        description="Testing to_dict output.",
        resource_id=None,
        severity=Severity.CRITICAL,
        nist_function="IDENTIFY",
        likelihood=1.0,
        impact=1.0,
        score=95.5,
    )

    result = finding.to_dict()

    # Ensure dict contains expected keys
    assert "id" in result
    assert "title" in result
    assert "description" in result
    assert "severity" in result
    assert "nist_function" in result
    assert "likelihood" in result
    assert "impact" in result
    assert "score" in result

    # Ensure values match
    assert result["severity"] == "CRITICAL"
    assert result["score"] == 95.5

