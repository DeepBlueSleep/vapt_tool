from scanner.checks.common import make_finding
from scanner.core.models import Classification, Confidence, FindingScope, ScanResult, Severity, TargetReport
from scanner.reporting.reports import deduplicate_findings, summarize_by_severity
from scanner.reporting.vapt import build_vapt_report, render_vapt_html, render_vapt_markdown


def test_deduplicate_findings() -> None:
    finding = make_finding(
        check="test",
        url="https://example.com",
        title="Missing header",
        severity=Severity.LOW,
        classification=Classification.RECOMMENDATION,
        confidence=Confidence.HIGH,
        evidence="x missing",
        remediation="set x",
    )
    report = TargetReport(input_url="https://example.com", findings=[finding, finding])
    deduplicate_findings(report)
    assert len(report.findings) == 1


def test_summary_by_severity() -> None:
    finding = make_finding(
        check="test",
        url="https://example.com",
        title="Issue",
        severity=Severity.HIGH,
        classification=Classification.WEAKNESS,
        confidence=Confidence.MEDIUM,
        evidence="evidence",
        remediation="fix",
    )
    assert summarize_by_severity([TargetReport(input_url="https://example.com", findings=[finding])])["high"] == 1


def test_vapt_report_groups_runtime_and_reduces_external_detail() -> None:
    finding = make_finding(
        check="runtime.api",
        url="https://example.com/api/users",
        title="Runtime API exposes diagnostic fields",
        severity=Severity.MEDIUM,
        classification=Classification.WEAKNESS,
        confidence=Confidence.HIGH,
        evidence="Diagnostic-like JSON fields: debug, trace",
        remediation="Remove debug fields from production API responses.",
        scope=FindingScope.ENDPOINT,
    )
    finding.occurrence_count = 37
    finding.affected_resources = [f"https://example.com/api/users?page={index}" for index in range(8)]
    report = TargetReport(
        input_url="https://example.com",
        findings=[finding],
        inventory={
            "runtime_apis": ["GET rest https://example.com/api/users"],
            "auth_signals": ["auth_required 0.90 https://example.com/api/users"],
        },
    )

    model = build_vapt_report([report], audience="external")
    html = render_vapt_html(ScanResult("now", [report]), "external")
    markdown = render_vapt_markdown(model)

    assert "Runtime/API Analysis" in model.finding_groups
    assert "37 endpoint-level location" in markdown
    assert "Executive Summary" in html
    assert "Detailed implementation guidance is intentionally excluded" in markdown
    assert "Browser instrumentation" in html
