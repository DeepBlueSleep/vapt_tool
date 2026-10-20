from __future__ import annotations

import datetime as dt
from dataclasses import dataclass
from enum import StrEnum
from platform.database.models import Finding as PersistedFinding
from platform.database.models import Scan
from typing import Any, TypeVar

from scanner.core.models import Classification, Confidence, Finding, FindingScope, Severity, TargetReport
from scanner.export.formats import to_sarif
from scanner.reporting.vapt import build_vapt_report, render_vapt_markdown, render_vapt_report_html, vapt_json_payload

EnumValue = TypeVar("EnumValue", bound=StrEnum)


@dataclass(frozen=True)
class ReportBundle:
    audience: str
    html: str
    markdown: str
    json_payload: dict[str, Any]
    sarif: dict[str, Any] | None = None


class ReportService:
    def build_external(self, scan: Scan) -> ReportBundle:
        target = _target_from_scan(scan)
        report = build_vapt_report([target], audience="external", generated_at_utc=_generated_at(scan))
        return ReportBundle(
            audience="external",
            html=render_vapt_report_html(report),
            markdown=render_vapt_markdown(report),
            json_payload=vapt_json_payload(report, include_internal=False),
        )

    def build_internal(self, scan: Scan) -> ReportBundle:
        target = _target_from_scan(scan)
        report = build_vapt_report([target], audience="internal", generated_at_utc=_generated_at(scan))
        return ReportBundle(
            audience="internal",
            html=render_vapt_report_html(report),
            markdown=render_vapt_markdown(report),
            json_payload=vapt_json_payload(report, include_internal=True),
            sarif=to_sarif([target]),
        )


def _target_from_scan(scan: Scan) -> TargetReport:
    findings = [_scanner_finding(finding) for finding in getattr(scan, "findings", []) if finding.state != "suppressed"]
    inventory = dict(scan.inventory or {})
    _merge_related_inventory(scan, inventory)
    metrics = {metric.name: metric.value for metric in getattr(scan, "metrics", [])}
    return TargetReport(
        input_url=scan.target_url,
        coverage_status=(inventory.get("assessment_status") or ["not_recorded"])[0],
        final_url=scan.target_url,
        pages_crawled=scan.pages_crawled,
        findings=findings,
        inventory=inventory,
        metrics=metrics,
        errors=[scan.error] if scan.error else [],
    )


def _scanner_finding(finding: PersistedFinding) -> Finding:
    metadata = dict(finding.metadata_json or {})
    return Finding(
        id=finding.scanner_finding_id or str(finding.id),
        title=finding.title,
        severity=_enum_or_default(Severity, finding.severity, Severity.INFO),
        classification=_enum_or_default(Classification, finding.classification, Classification.RECOMMENDATION),
        confidence=_enum_or_default(Confidence, finding.confidence, Confidence.MEDIUM),
        evidence=finding.evidence_summary,
        remediation=finding.remediation,
        url=finding.url,
        check=str(metadata.get("check", "platform.persisted")),
        scope=_enum_or_default(FindingScope, finding.scope, FindingScope.ENDPOINT),
        dedup_key=finding.dedup_key,
        affected_resources=list(finding.affected_resources or [finding.url]),
        evidence_items=[finding.evidence_summary],
        occurrence_count=max(1, finding.occurrence_count or 1),
        metadata=metadata,
    )


def _merge_related_inventory(scan: Scan, inventory: dict[str, Any]) -> None:
    if getattr(scan, "routes", None):
        inventory.setdefault("browser_routes", [])
        inventory["browser_routes"].extend(route.url for route in scan.routes if route.url not in inventory["browser_routes"])
    if getattr(scan, "runtime_apis", None):
        inventory.setdefault("runtime_apis", [])
        for api in scan.runtime_apis:
            item = f"{api.method} {api.kind} {api.url}"
            if item not in inventory["runtime_apis"]:
                inventory["runtime_apis"].append(item)
    if getattr(scan, "parameters", None):
        inventory.setdefault("runtime_parameters", [])
        for parameter in scan.parameters:
            item = f"{parameter.method} {parameter.name} ({parameter.param_type}) from {parameter.source}"
            if item not in inventory["runtime_parameters"]:
                inventory["runtime_parameters"].append(item)
    if getattr(scan, "auth_signals", None):
        inventory.setdefault("auth_signals", [])
        for signal in scan.auth_signals:
            item = f"{signal.kind} {signal.confidence:.2f} {signal.url}"
            if item not in inventory["auth_signals"]:
                inventory["auth_signals"].append(item)
    if getattr(scan, "evidence", None):
        inventory.setdefault("screenshots", [])
        for evidence_item in scan.evidence:
            if (
                evidence_item.kind == "screenshot"
                and evidence_item.storage_path
                and evidence_item.storage_path not in inventory["screenshots"]
            ):
                inventory["screenshots"].append(evidence_item.storage_path)


def _generated_at(scan: Scan) -> str:
    value = scan.completed_at or scan.started_at or scan.created_at or dt.datetime.now(dt.UTC)
    return value.isoformat()


def _enum_or_default(enum_type: type[EnumValue], value: str, default: EnumValue) -> EnumValue:
    try:
        return enum_type(value)
    except ValueError:
        return default
