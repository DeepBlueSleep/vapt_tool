from __future__ import annotations

import urllib.parse
from dataclasses import dataclass

from scanner.core.models import Confidence, Finding, FindingScope, TargetReport


@dataclass(frozen=True)
class AggregationPolicy:
    max_samples: int = 10


def infer_scope(finding: Finding) -> FindingScope:
    title = finding.title.lower()
    if any(token in title for token in ("strict transport security", "content security policy", "x-content-type", "referrer-policy")):
        return FindingScope.HOST
    if "cookie" in title:
        return FindingScope.ENDPOINT
    if "reflected" in title or "parameter" in title:
        return FindingScope.PARAMETER
    if "directory listing" in title:
        return FindingScope.PATH
    return finding.scope


def normalized_dedup_key(finding: Finding) -> str:
    scope = infer_scope(finding)
    parsed = urllib.parse.urlparse(finding.url)
    host = parsed.netloc.lower()
    path = parsed.path.rstrip("/") or "/"
    if finding.dedup_key:
        return finding.dedup_key
    if scope == FindingScope.GLOBAL:
        resource = "global"
    elif scope == FindingScope.HOST:
        resource = host
    elif scope == FindingScope.PATH:
        resource = f"{host}{path}"
    elif scope == FindingScope.PARAMETER:
        parameter = str(finding.metadata.get("parameter", ""))
        endpoint = str(finding.metadata.get("endpoint", f"{host}{path}"))
        resource = f"{endpoint}:{parameter}"
    else:
        resource = f"{host}{path}"
    return "|".join((finding.check, scope.value, finding.title.lower(), resource))


def aggregate_findings(findings: list[Finding], policy: AggregationPolicy | None = None) -> list[Finding]:
    policy = policy or AggregationPolicy()
    grouped: dict[str, Finding] = {}
    for finding in findings:
        finding.scope = infer_scope(finding)
        key = normalized_dedup_key(finding)
        finding.dedup_key = key
        if key not in grouped:
            finding.affected_resources = list(dict.fromkeys(finding.affected_resources or [finding.url]))[: policy.max_samples]
            finding.evidence_items = list(dict.fromkeys(finding.evidence_items or [finding.evidence]))[: policy.max_samples]
            finding.occurrence_count = max(1, finding.occurrence_count)
            grouped[key] = finding
            continue
        current = grouped[key]
        current.occurrence_count += 1
        for resource in finding.affected_resources or [finding.url]:
            if resource not in current.affected_resources and len(current.affected_resources) < policy.max_samples:
                current.affected_resources.append(resource)
        for evidence in finding.evidence_items or [finding.evidence]:
            if evidence not in current.evidence_items and len(current.evidence_items) < policy.max_samples:
                current.evidence_items.append(evidence)
        current.confidence = _max_confidence(current.confidence, finding.confidence)
    return sorted(grouped.values(), key=correlated_risk_score, reverse=True)


def correlated_risk_score(finding: Finding) -> float:
    scope_weight = {
        FindingScope.GLOBAL: 1.15,
        FindingScope.HOST: 1.1,
        FindingScope.PATH: 1.0,
        FindingScope.ENDPOINT: 1.0,
        FindingScope.PARAMETER: 1.05,
    }[finding.scope]
    occurrence_bonus = min(10.0, max(0, finding.occurrence_count - 1) * 0.5)
    exploitability = float(finding.metadata.get("exploitability", 1.0))
    return min(100.0, round((finding.risk_score * scope_weight * exploitability) + occurrence_bonus, 1))


def finalize_report_findings(report: TargetReport) -> None:
    report.aggregated_findings = aggregate_findings(report.findings)
    report.findings = report.aggregated_findings


def _max_confidence(left: Confidence, right: Confidence) -> Confidence:
    rank = {Confidence.LOW: 0, Confidence.MEDIUM: 1, Confidence.HIGH: 2}
    return left if rank[left] >= rank[right] else right
