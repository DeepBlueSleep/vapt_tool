from __future__ import annotations

import csv
import json
from dataclasses import asdict
from io import StringIO

from scanner.core.models import TargetReport
from scanner.reporting.compliance import map_finding


def to_sarif(reports: list[TargetReport]) -> dict[str, object]:
    results = []
    rules = {}
    for report in reports:
        for finding in report.findings:
            rules[finding.id] = {"id": finding.id, "name": finding.title, "shortDescription": {"text": finding.title}}
            results.append(
                {
                    "ruleId": finding.id,
                    "level": _sarif_level(finding.severity.value),
                    "message": {"text": finding.evidence},
                    "locations": [{"physicalLocation": {"artifactLocation": {"uri": finding.url}}}],
                }
            )
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{"tool": {"driver": {"name": "Safe Website Scanner", "rules": list(rules.values())}}, "results": results}],
    }


def to_csv(reports: list[TargetReport]) -> str:
    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(["target", "severity", "confidence", "title", "url", "occurrences", "remediation"])
    for report in reports:
        for finding in report.findings:
            writer.writerow(
                [
                    report.input_url,
                    finding.severity.value,
                    finding.confidence.value,
                    finding.title,
                    finding.url,
                    finding.occurrence_count,
                    finding.remediation,
                ]
            )
    return output.getvalue()


def to_junit(reports: list[TargetReport]) -> str:
    cases = []
    failures = 0
    for report in reports:
        for finding in report.findings:
            failed = finding.severity.value in {"critical", "high"}
            failures += int(failed)
            failure_xml = f"<failure message=\"{_xml(finding.title)}\">{_xml(finding.evidence)}</failure>" if failed else ""
            cases.append(f"<testcase classname=\"security\" name=\"{_xml(finding.title)}\">{failure_xml}</testcase>")
    return f"<testsuite name=\"security-scan\" tests=\"{len(cases)}\" failures=\"{failures}\">{''.join(cases)}</testsuite>"


def to_github_security(reports: list[TargetReport]) -> dict[str, object]:
    return {
        "findings": [
            {
                "title": finding.title,
                "severity": finding.severity.value,
                "description": finding.evidence,
                "location": finding.url,
                "identifiers": asdict(map_finding(finding)),
            }
            for report in reports
            for finding in report.findings
        ]
    }


def to_markdown_bundle(reports: list[TargetReport]) -> dict[str, str]:
    return {
        "sarif.json": json.dumps(to_sarif(reports), indent=2),
        "findings.csv": to_csv(reports),
        "junit.xml": to_junit(reports),
        "github-security.json": json.dumps(to_github_security(reports), indent=2),
    }


def _sarif_level(severity: str) -> str:
    return {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "none"}.get(severity, "warning")


def _xml(value: str) -> str:
    return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")
