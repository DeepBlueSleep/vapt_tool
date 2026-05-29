from scanner.checks.common import make_finding
from scanner.core.models import Classification, Confidence, FindingScope, Severity, TargetReport
from scanner.risk.correlation import finalize_report_findings


def test_host_findings_are_aggregated() -> None:
    findings = [
        make_finding(
            check="passive.headers",
            url=f"https://example.com/page{i}",
            title="Missing HTTP Strict Transport Security",
            severity=Severity.HIGH,
            classification=Classification.RECOMMENDATION,
            confidence=Confidence.HIGH,
            evidence="hsts missing",
            remediation="add hsts",
            scope=FindingScope.HOST,
        )
        for i in range(3)
    ]
    report = TargetReport(input_url="https://example.com", findings=findings)
    finalize_report_findings(report)
    assert len(report.findings) == 1
    assert report.findings[0].occurrence_count == 3
    assert len(report.findings[0].affected_resources) == 3
