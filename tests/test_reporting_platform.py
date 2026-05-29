import json
from pathlib import Path

from scanner.checks.common import make_finding
from scanner.core.models import Classification, Confidence, FindingScope, ScanResult, Severity, TargetReport
from scanner.export.formats import to_csv, to_sarif
from scanner.prioritization.engine import prioritize_findings
from scanner.remediation.engine import remediation_for
from scanner.reporting.attack_surface import summarize_attack_surface
from scanner.reporting.compliance import map_finding
from scanner.reporting.developer import render_developer_markdown
from scanner.reporting.diff import compare_report_files
from scanner.reporting.executive import build_executive_report
from scanner.reporting.explanations import explain_finding
from scanner.reporting.html_modern import render_modern_html
from scanner.risk.posture import score_posture


def _sample_report() -> TargetReport:
    finding = make_finding(
        check="passive.headers",
        url="https://example.com/",
        title="Missing Content Security Policy",
        severity=Severity.MEDIUM,
        classification=Classification.RECOMMENDATION,
        confidence=Confidence.HIGH,
        evidence="content-security-policy header was not present.",
        remediation="Add a restrictive Content-Security-Policy header.",
        scope=FindingScope.HOST,
    )
    finding.occurrence_count = 3
    return TargetReport(
        input_url="https://example.com",
        final_url="https://example.com/",
        pages_crawled=3,
        findings=[finding],
        technologies={"js_framework:react": "detected"},
        inventory={
            "pages": ["https://example.com/"],
            "runtime_apis": ["GET rest https://example.com/api/users"],
            "auth_signals": ["login_form 0.95 https://example.com/login"],
            "parameters": ["GET q (query) from https://example.com/search?q=x"],
        },
    )


def test_explain_remediate_and_posture() -> None:
    report = _sample_report()
    explanation = explain_finding(report.findings[0])
    advice = remediation_for(report.findings[0], report)
    posture = score_posture(report)
    assert "Client-side injection" in explanation.why_it_matters
    assert "CSP" in advice.summary
    assert posture.grade in {"A", "B", "C", "D", "F"}


def test_executive_html_developer_and_exports() -> None:
    report = _sample_report()
    executive = build_executive_report([report])
    html = render_modern_html(ScanResult("now", [report]), "executive")
    developer = render_developer_markdown([report])
    sarif = to_sarif([report])
    csv = to_csv([report])
    assert "assessment covered" in executive.summary
    assert "Security Assessment Dashboard" in html
    assert "Developer Remediation Guide" in developer
    assert sarif["version"] == "2.1.0"
    assert "Missing Content Security Policy" in csv


def test_attack_surface_compliance_prioritization() -> None:
    report = _sample_report()
    surface = summarize_attack_surface(report)
    mapping = map_finding(report.findings[0])
    priority = prioritize_findings(report)[0]
    assert surface.runtime_apis == 1
    assert any("Injection" in item for item in mapping.owasp)
    assert priority.priority > 0


def test_diff_reporting(tmp_path: Path) -> None:
    previous = tmp_path / "previous.json"
    current = tmp_path / "current.json"
    previous.write_text(json.dumps({"targets": [{"findings": [{"id": "old"}], "inventory": {"pages": ["a"]}}]}), encoding="utf-8")
    current.write_text(json.dumps({"targets": [{"findings": [{"id": "new"}], "inventory": {"pages": ["b"]}}]}), encoding="utf-8")
    diff = compare_report_files(previous, current)
    assert diff.new_findings == ("new",)
    assert diff.fixed_findings == ("old",)
    assert diff.attack_surface_changes == ("pages:a", "pages:b")
