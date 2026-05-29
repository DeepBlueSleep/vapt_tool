from __future__ import annotations

from dataclasses import dataclass

from scanner.core.models import Finding, TargetReport
from scanner.risk.correlation import correlated_risk_score


@dataclass(frozen=True)
class PrioritizedItem:
    title: str
    reason: str
    priority: float
    owner_hint: str


def prioritize_findings(report: TargetReport, limit: int = 10) -> tuple[PrioritizedItem, ...]:
    items = []
    for finding in report.findings:
        score = correlated_risk_score(finding)
        reason = (
            f"{finding.severity.value.title()} severity, {finding.confidence.value} confidence, "
            f"{finding.occurrence_count} occurrence(s)."
        )
        if "auth" in finding.url.lower() or "cookie" in finding.title.lower():
            score += 8
            reason += " Authentication/session surface increases priority."
        if "graphql" in finding.title.lower() or "api" in finding.url.lower():
            score += 6
            reason += " API exposure increases priority."
        items.append(PrioritizedItem(finding.title, reason, min(100.0, round(score, 1)), _owner_hint(finding)))
    return tuple(sorted(items, key=lambda item: item.priority, reverse=True)[:limit])


def _owner_hint(finding: Finding) -> str:
    title = finding.title.lower()
    if "header" in title or "hsts" in title or "csp" in title:
        return "platform / edge / web application team"
    if "cookie" in title or "auth" in title:
        return "application authentication team"
    if "api" in finding.url.lower() or "graphql" in title:
        return "API service owner"
    return "application owner"
