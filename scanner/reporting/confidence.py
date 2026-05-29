from __future__ import annotations

from dataclasses import dataclass

from scanner.core.models import Confidence, Finding


@dataclass(frozen=True)
class ConfidenceSummary:
    high: int
    medium: int
    low: int
    validated: int
    browser_confirmed: int
    heuristic: int


def summarize_confidence(findings: list[Finding]) -> ConfidenceSummary:
    return ConfidenceSummary(
        high=sum(1 for finding in findings if finding.confidence == Confidence.HIGH),
        medium=sum(1 for finding in findings if finding.confidence == Confidence.MEDIUM),
        low=sum(1 for finding in findings if finding.confidence == Confidence.LOW),
        validated=sum(1 for finding in findings if "validated" in str(finding.metadata).lower()),
        browser_confirmed=sum(1 for finding in findings if "browser" in finding.check or "runtime" in finding.check),
        heuristic=sum(1 for finding in findings if finding.confidence != Confidence.HIGH),
    )


def confidence_rationale(finding: Finding) -> str:
    if finding.confidence == Confidence.HIGH:
        return "High confidence: the scanner directly observed the missing control or validated behavior without exploit attempts."
    if finding.confidence == Confidence.MEDIUM:
        return "Medium confidence: the scanner observed a strong heuristic or runtime signal that should be manually confirmed."
    return "Low confidence: this is a weak signal intended for triage and correlation with other evidence."
