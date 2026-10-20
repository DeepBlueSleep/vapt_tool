from __future__ import annotations

from dataclasses import dataclass

from scanner.core.models import Severity, TargetReport
from scanner.reporting.attack_surface import summarize_attack_surface
from scanner.risk.correlation import correlated_risk_score


@dataclass(frozen=True)
class PostureScore:
    score: float
    grade: str
    api_exposure: float
    auth_exposure: float
    browser_runtime_complexity: float
    third_party_exposure: float
    missing_controls: float
    summary: str


def score_posture(report: TargetReport) -> PostureScore:
    surface = summarize_attack_surface(report)
    max_risk = max((correlated_risk_score(finding) for finding in report.findings), default=0.0)
    critical_high = sum(1 for finding in report.findings if finding.severity in {Severity.CRITICAL, Severity.HIGH})
    api_exposure = min(100.0, surface.apis * 4 + surface.runtime_apis * 5)
    auth_exposure = min(100.0, surface.auth_routes * 8 + len(report.inventory.get("auth_signals", [])) * 3)
    runtime = min(100.0, surface.complexity_score)
    third_party = min(100.0, surface.external_services * 8)
    missing_controls = min(100.0, sum(10 for finding in report.findings if "missing" in finding.title.lower()))
    penalty = max_risk * 0.45 + critical_high * 8 + api_exposure * 0.12 + auth_exposure * 0.1 + runtime * 0.08 + third_party * 0.08
    score = max(0.0, round(100.0 - penalty, 1))
    return PostureScore(
        score=0.0 if report.coverage_status == "failed" else score,
        grade="n/a" if report.coverage_status == "failed" else _grade(score),
        api_exposure=round(api_exposure, 1),
        auth_exposure=round(auth_exposure, 1),
        browser_runtime_complexity=round(runtime, 1),
        third_party_exposure=round(third_party, 1),
        missing_controls=round(missing_controls, 1),
        summary=("Assessment failed; security posture could not be established." if report.coverage_status == "failed"
                 else ("Partial assessment. " if report.coverage_status == "partial" else "") + _summary(score)),
    )


def _grade(score: float) -> str:
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    return "F"


def _summary(score: float) -> str:
    if score >= 85:
        return "The observed posture is strong for the configured checks, with limited high-priority remediation."
    if score >= 70:
        return "The observed posture is workable, but several hardening and validation tasks should be prioritized."
    return "The observed posture needs focused remediation and follow-up validation."
