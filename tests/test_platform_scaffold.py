import importlib.util

import pytest


def test_platform_package_preserves_stdlib_platform_helpers() -> None:
    import platform

    assert isinstance(platform.system(), str)
    assert isinstance(platform.python_version(), str)


@pytest.mark.skipif(importlib.util.find_spec("sqlalchemy") is None, reason="platform optional dependencies are not installed")
def test_external_report_omits_internal_remediation_details() -> None:
    from platform.database.models import Finding, Scan
    from platform.reporting.service import ReportService

    scan = Scan(target_url="https://example.com", posture_score=82.0, posture_grade="B", inventory={"runtime_apis": ["GET rest /api"]})
    scan.findings = [
        Finding(
            scanner_finding_id="f1",
            dedup_key="f1",
            title="Missing Content Security Policy",
            severity="medium",
            classification="recommendation",
            confidence="high",
            url="https://example.com",
            scope="host",
            evidence_summary="content-security-policy header was not present.",
            remediation="Add nginx add_header Content-Security-Policy with a restrictive policy.",
            risk_score=55.0,
        )
    ]

    external = ReportService().build_external(scan)
    internal = ReportService().build_internal(scan)

    assert "Detailed implementation guidance is intentionally excluded" in external.markdown
    assert "nginx" not in external.markdown.lower()
    assert "Implementation Example" in internal.markdown
    assert "Content-Security-Policy" in internal.markdown
