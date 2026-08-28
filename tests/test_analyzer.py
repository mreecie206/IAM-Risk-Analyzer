# tests/test_analyzer.py

import json
import os
import pytest

from src.analyzer import Analyzer
from src.models import Severity


@pytest.fixture
def sample_config():
    """Load the sample IAM config JSON for testing."""
    path = os.path.join(os.path.dirname(__file__), "..", "src", "Sample", "sample_config.json")
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def test_analyzer_produces_findings(sample_config):
    analyzer = Analyzer()
    report = analyzer.analyze(sample_config)

    # Ensure we got findings
    assert len(report.findings) > 0

    # Ensure total score is positive
    assert report.total_score > 0

    # Ensure severity breakdown includes CRITICAL and HIGH
    severities = {sev.value for sev in report.by_severity.keys()}
    assert Severity.CRITICAL.value in severities or Severity.HIGH.value in severities


def test_analyzer_counts_by_nist_function(sample_config):
    analyzer = Analyzer()
    report = analyzer.analyze(sample_config)

    # Ensure NIST function counts exist
    assert isinstance(report.by_nist_function, dict)
    assert "PROTECT" in report.by_nist_function
    assert report.by_nist_function["PROTECT"] > 0


def test_report_serialization(sample_config):
    analyzer = Analyzer()
    report = analyzer.analyze(sample_config)

    # JSON serialization should produce a string
    json_output = report.to_json()
    assert isinstance(json_output, str)

    # Dict serialization should include keys
    dict_output = report.to_dict()
    assert "total_score" in dict_output
    assert "findings" in dict_output
    assert "by_severity" in dict_output
    assert "by_nist_function" in dict_output

