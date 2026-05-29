from __future__ import annotations

import hashlib

from scanner.core.models import Classification, Confidence, Finding, FindingScope, Reference, Severity


def finding_id(check: str, url: str, title: str, evidence: str) -> str:
    digest = hashlib.sha256(f"{check}|{url}|{title}|{evidence}".encode()).hexdigest()[:16]
    return f"{check}:{digest}"


def make_finding(
    *,
    check: str,
    url: str,
    title: str,
    severity: Severity,
    classification: Classification,
    confidence: Confidence,
    evidence: str,
    remediation: str,
    scope: FindingScope = FindingScope.ENDPOINT,
    dedup_key: str | None = None,
    references: list[Reference] | None = None,
    metadata: dict[str, object] | None = None,
) -> Finding:
    return Finding(
        id=finding_id(check, url, title, evidence),
        check=check,
        url=url,
        title=title,
        severity=severity,
        classification=classification,
        confidence=confidence,
        evidence=evidence,
        remediation=remediation,
        scope=scope,
        dedup_key=dedup_key,
        affected_resources=[url],
        evidence_items=[evidence],
        references=references or [],
        metadata=metadata or {},
    )
