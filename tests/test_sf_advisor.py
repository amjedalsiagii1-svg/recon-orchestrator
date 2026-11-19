"""Tests for SF's explainable advisory engine."""
from sf_desktop.advisor import (
    SAFE_COMMANDS,
    commands_for_report,
    recommendations_for_evidence,
    severity_counts,
)


def test_severity_is_counted_only_when_explicitly_stored():
    records = [
        {"category": "finding", "payload": {"severity": "high"}},
        {"category": "finding", "payload": {"severity": "unknown"}},
        {"category": "note", "payload": {}},
    ]
    counts = severity_counts(records)
    assert counts["high"] == 1
    assert counts["unspecified"] == 2


def test_recommendations_are_deterministic_and_deduplicated_by_category():
    records = [
        {"category": "service", "payload": {}},
        {"category": "service", "payload": {}},
        {"category": "finding", "payload": {"severity": "high"}},
    ]
    recommendations = recommendations_for_evidence(records)
    assert recommendations[0]["category"] == "service"
    assert sum(r["category"] == "service" for r in recommendations) == 1
    assert any("عالية" in r["title"] for r in recommendations)


def test_command_catalog_is_local_read_only_and_has_explanations():
    commands = commands_for_report()
    assert len(commands) >= 5
    assert all(c.command and c.purpose and c.expected and c.prerequisites for c in commands)
    assert all("nmap" not in c.command.lower() for c in commands)
