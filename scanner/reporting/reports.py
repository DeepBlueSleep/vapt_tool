from __future__ import annotations

import datetime as dt
import json
from dataclasses import asdict
from pathlib import Path

from scanner.core.models import Classification, ScanResult, Severity, TargetReport
from scanner.export.formats import to_csv, to_github_security, to_junit, to_sarif
from scanner.reporting.compliance import compliance_summary, map_finding
from scanner.reporting.developer import render_developer_markdown
from scanner.reporting.executive import render_executive_markdown
from scanner.reporting.html_modern import render_modern_html
from scanner.risk.correlation import correlated_risk_score


def summarize_by_severity(reports: list[TargetReport]) -> dict[str, int]:
    counts = {severity.value: 0 for severity in Severity}
    for report in reports:
        for finding in report.findings:
            counts[finding.severity.value] += 1
    return counts


def summarize_by_classification(reports: list[TargetReport]) -> dict[str, int]:
    counts = {classification.value: 0 for classification in Classification}
    for report in reports:
        for finding in report.findings:
            counts[finding.classification.value] += 1
    return counts


def deduplicate_findings(report: TargetReport) -> None:
    seen = set()
    unique = []
    for finding in report.findings:
        if finding.id in seen:
            continue
        seen.add(finding.id)
        unique.append(finding)
    report.findings = sorted(unique, key=correlated_risk_score, reverse=True)


def write_reports(
    reports: list[TargetReport],
    out_dir: Path,
    report_mode: str = "technical",
    export_formats: tuple[str, ...] = (),
) -> tuple[Path, Path, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    timestamp = dt.datetime.now(dt.UTC).strftime("%Y%m%d-%H%M%S")
    result = ScanResult(generated_at_utc=dt.datetime.now(dt.UTC).isoformat(), targets=reports)
    json_path = out_dir / f"website-audit-{timestamp}.json"
    md_path = out_dir / f"website-audit-{timestamp}.md"
    html_path = out_dir / f"website-audit-{timestamp}.html"
    json_path.write_text(json.dumps(_json_payload(result), indent=2), encoding="utf-8")
    md_path.write_text(render_report_markdown(result, report_mode), encoding="utf-8")
    html_path.write_text(render_modern_html(result, report_mode), encoding="utf-8")
    _write_exports(reports, out_dir, timestamp, export_formats)
    return json_path, md_path, html_path


def _json_payload(result: ScanResult) -> dict[str, object]:
    return {
        "generated_at_utc": result.generated_at_utc,
        "summary": {
            "by_severity": summarize_by_severity(result.targets),
            "by_classification": summarize_by_classification(result.targets),
            "compliance": compliance_summary(result.targets),
        },
        "targets": [asdict(target) for target in result.targets],
    }


def render_report_markdown(result: ScanResult, report_mode: str) -> str:
    if report_mode == "executive":
        return render_executive_markdown(result.targets)
    if report_mode == "developer":
        return render_developer_markdown(result.targets)
    if report_mode == "compliance":
        return _render_compliance_markdown(result.targets)
    if report_mode == "api-focused":
        return _render_inventory_markdown(result.targets, ("api_surfaces", "runtime_apis", "endpoints", "runtime_parameters"))
    if report_mode == "runtime-focused":
        return _render_inventory_markdown(result.targets, ("browser_routes", "runtime_apis", "dynamic_forms", "browser_network"))
    return render_markdown(result)


def render_markdown(result: ScanResult) -> str:
    severity_summary = summarize_by_severity(result.targets)
    classification_summary = summarize_by_classification(result.targets)
    lines = [
        "# Website Security Assessment Report",
        "",
        f"Generated: {result.generated_at_utc}",
        "",
        "## Executive Summary",
        "",
        f"- Targets scanned: {len(result.targets)}",
        f"- Aggregated findings: {sum(len(target.findings) for target in result.targets)}",
        f"- Critical/high findings: {severity_summary['critical'] + severity_summary['high']}",
        "",
        "## Summary By Classification",
        "",
        "| Classification | Count |",
        "| --- | ---: |",
    ]
    for classification in ("vulnerability", "weakness", "recommendation"):
        lines.append(f"| {classification.title()} | {classification_summary[classification]} |")
    lines.extend(["", "## Summary By Severity", "", "| Severity | Count |", "| --- | ---: |"])
    for severity in ("critical", "high", "medium", "low", "info"):
        lines.append(f"| {severity.title()} | {severity_summary[severity]} |")
    for target in result.targets:
        lines.extend(
            [
                "",
                f"## Target: {target.input_url}",
                "",
                f"- Final URL: {target.final_url or 'n/a'}",
                f"- Status: {target.status_code or 'n/a'}",
                f"- Pages crawled: {target.pages_crawled}",
                f"- Risk score: {_target_risk(target)}",
            ]
        )
        if target.metrics:
            lines.append(f"- HTTP requests: {target.metrics.get('http_requests', 0)}")
        if target.technologies:
            lines.append(f"- Technologies: {', '.join(f'{k}={v}' for k, v in sorted(target.technologies.items()))}")
        if target.inventory.get("endpoints"):
            lines.append(f"- Endpoints discovered: {len(target.inventory['endpoints'])}")
        if target.inventory.get("parameters"):
            lines.append(f"- Parameters discovered: {len(target.inventory['parameters'])}")
        if target.inventory.get("runtime_apis"):
            lines.append(f"- Runtime APIs discovered: {len(target.inventory['runtime_apis'])}")
        if target.inventory.get("expanded_attack_surface"):
            lines.append(f"- Expanded attack surface candidates: {len(target.inventory['expanded_attack_surface'])}")
        if target.inventory.get("verified_expanded_routes"):
            lines.append(f"- Verified expanded routes: {len(target.inventory['verified_expanded_routes'])}")
        if target.inventory.get("browser_routes"):
            lines.append(f"- Browser routes discovered: {len(target.inventory['browser_routes'])}")
        if target.inventory.get("dynamic_forms"):
            lines.append(f"- Dynamic forms discovered: {len(target.inventory['dynamic_forms'])}")
        if target.errors:
            lines.append(f"- Errors: {'; '.join(target.errors)}")
        if not target.findings:
            lines.extend(["", "No findings detected by the configured checks."])
            continue
        lines.extend(
            [
                "",
                "| Risk | Scope | Count | Severity | Confidence | Finding | Evidence Samples | Affected Resource Samples | Remediation |",
                "| ---: | --- | ---: | --- | --- | --- | --- | --- | --- |",
            ]
        )
        for finding in target.findings:
            title = _escape_table(finding.title)
            evidence = _escape_table("; ".join(finding.evidence_items or [finding.evidence]))
            affected = _escape_table("; ".join(finding.affected_resources or [finding.url]))
            remediation = _escape_table(finding.remediation)
            lines.append(
                f"| {correlated_risk_score(finding)} | {finding.scope.value} | {finding.occurrence_count} | "
                f"{finding.severity.value.title()} | {finding.confidence.value.title()} | {title} | "
                f"{evidence} | {affected} | {remediation} |"
            )
    return "\n".join(lines) + "\n"


def has_blocking_vulnerability(reports: list[TargetReport]) -> bool:
    return any(
        finding.classification == Classification.VULNERABILITY and finding.severity in {Severity.CRITICAL, Severity.HIGH}
        for report in reports
        for finding in report.findings
    )


def _target_risk(target: TargetReport) -> float:
    return max((correlated_risk_score(finding) for finding in target.findings), default=0.0)


def _escape_table(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ")


def _render_compliance_markdown(reports: list[TargetReport]) -> str:
    lines = [
        "# Compliance Mapping",
        "",
        "| Target | Finding | OWASP | ASVS | CWE | PCI DSS | SOC2 | ISO 27001 |",
        "| --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for report in reports:
        for finding in report.findings:
            mapping = map_finding(finding)
            lines.append(
                f"| {_escape_table(report.input_url)} | {_escape_table(finding.title)} | {', '.join(mapping.owasp)} | "
                f"{', '.join(mapping.asvs)} | {', '.join(mapping.cwe)} | {', '.join(mapping.pci_dss)} | "
                f"{', '.join(mapping.soc2)} | {', '.join(mapping.iso27001)} |"
            )
    return "\n".join(lines) + "\n"


def _render_inventory_markdown(reports: list[TargetReport], keys: tuple[str, ...]) -> str:
    lines = ["# Attack Surface Inventory", ""]
    for report in reports:
        lines.extend([f"## {report.input_url}", ""])
        for key in keys:
            values = report.inventory.get(key, [])
            lines.extend([f"### {key} ({len(values)})", ""])
            lines.extend(f"- {value}" for value in values[:100])
            lines.append("")
    return "\n".join(lines)


def _write_exports(reports: list[TargetReport], out_dir: Path, timestamp: str, formats: tuple[str, ...]) -> None:
    for fmt in formats:
        normalized = fmt.lower()
        if normalized == "sarif":
            (out_dir / f"website-audit-{timestamp}.sarif.json").write_text(json.dumps(to_sarif(reports), indent=2), encoding="utf-8")
        elif normalized == "csv":
            (out_dir / f"website-audit-{timestamp}.csv").write_text(to_csv(reports), encoding="utf-8")
        elif normalized == "junit":
            (out_dir / f"website-audit-{timestamp}.junit.xml").write_text(to_junit(reports), encoding="utf-8")
        elif normalized == "github-security":
            (out_dir / f"website-audit-{timestamp}.github-security.json").write_text(
                json.dumps(to_github_security(reports), indent=2),
                encoding="utf-8",
            )
