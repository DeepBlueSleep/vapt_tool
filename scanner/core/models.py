from __future__ import annotations

import datetime as dt
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Classification(StrEnum):
    RECOMMENDATION = "recommendation"
    WEAKNESS = "weakness"
    VULNERABILITY = "vulnerability"


class Confidence(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class FindingScope(StrEnum):
    GLOBAL = "global"
    HOST = "host"
    PATH = "path"
    ENDPOINT = "endpoint"
    PARAMETER = "parameter"


SEVERITY_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}

CLASSIFICATION_RANK = {
    Classification.RECOMMENDATION: 0,
    Classification.WEAKNESS: 1,
    Classification.VULNERABILITY: 2,
}


@dataclass(frozen=True)
class Reference:
    title: str
    url: str


@dataclass
class Finding:
    id: str
    title: str
    severity: Severity
    classification: Classification
    confidence: Confidence
    evidence: str
    remediation: str
    url: str
    check: str
    scope: FindingScope = FindingScope.ENDPOINT
    dedup_key: str | None = None
    affected_resources: list[str] = field(default_factory=list)
    evidence_items: list[str] = field(default_factory=list)
    occurrence_count: int = 1
    references: list[Reference] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def risk_score(self) -> float:
        base = float(SEVERITY_RANK[self.severity] * 20)
        confidence_weight = {
            Confidence.LOW: 0.55,
            Confidence.MEDIUM: 0.75,
            Confidence.HIGH: 1.0,
        }[self.confidence]
        class_bonus = {
            Classification.RECOMMENDATION: 0,
            Classification.WEAKNESS: 8,
            Classification.VULNERABILITY: 15,
        }[self.classification]
        return min(100.0, round(base * confidence_weight + class_bonus, 1))

    def normalized_key(self) -> str:
        if self.dedup_key:
            return self.dedup_key
        return "|".join((self.check, self.scope.value, self.title.lower(), self._normalized_resource()))

    def _normalized_resource(self) -> str:
        if self.scope in {FindingScope.GLOBAL, FindingScope.HOST}:
            return str(self.metadata.get("host", ""))
        if self.scope == FindingScope.PATH:
            return str(self.metadata.get("path", self.url))
        if self.scope == FindingScope.PARAMETER:
            return f"{self.metadata.get('endpoint', self.url)}:{self.metadata.get('parameter', '')}"
        return self.url


@dataclass(frozen=True)
class Form:
    action: str
    method: str
    has_password: bool
    inputs: tuple[str, ...] = ()
    hidden_inputs: tuple[str, ...] = ()


@dataclass(frozen=True)
class Page:
    url: str
    final_url: str
    status: int | None
    headers: dict[str, list[str]]
    body: bytes
    content_type: str = ""
    links: tuple[str, ...] = ()
    assets: tuple[str, ...] = ()
    scripts: tuple[str, ...] = ()
    forms: tuple[Form, ...] = ()
    parameters: tuple[str, ...] = ()


@dataclass
class TargetReport:
    input_url: str
    final_url: str | None = None
    status_code: int | None = None
    scanned_at_utc: str = field(default_factory=lambda: dt.datetime.now(dt.UTC).isoformat())
    pages_crawled: int = 0
    findings: list[Finding] = field(default_factory=list)
    aggregated_findings: list[Finding] = field(default_factory=list)
    technologies: dict[str, str] = field(default_factory=dict)
    inventory: dict[str, list[str]] = field(default_factory=dict)
    metrics: dict[str, int | float] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    coverage_status: str = "not_recorded"


@dataclass(frozen=True)
class ScanResult:
    generated_at_utc: str
    targets: list[TargetReport]
