from __future__ import annotations

from dataclasses import dataclass

from scanner.core.models import Finding, TargetReport


@dataclass(frozen=True)
class EvidenceLineage:
    finding_id: str
    request_url: str
    response_summary: str
    discovery_path: tuple[str, ...]
    browser_evidence: tuple[str, ...]
    screenshot_refs: tuple[str, ...]
    js_sources: tuple[str, ...]


def lineage_for(finding: Finding, report: TargetReport) -> EvidenceLineage:
    discovery = []
    if finding.url in report.inventory.get("browser_routes", []):
        discovery.append("browser route discovery")
    if any(finding.url in item for item in report.inventory.get("runtime_apis", [])):
        discovery.append("runtime API capture")
    if any(finding.url in item for item in report.inventory.get("js_endpoints", [])):
        discovery.append("JavaScript endpoint extraction")
    if not discovery:
        discovery.append("crawler or passive response analysis")
    return EvidenceLineage(
        finding_id=finding.id,
        request_url=finding.url,
        response_summary="; ".join(finding.evidence_items[:3] or [finding.evidence]),
        discovery_path=tuple(discovery),
        browser_evidence=tuple(report.inventory.get("browser_network", [])[:5]),
        screenshot_refs=tuple(report.inventory.get("screenshots", [])),
        js_sources=tuple(report.inventory.get("assets", [])[:5]),
    )
