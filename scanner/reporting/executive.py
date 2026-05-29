from __future__ import annotations

from dataclasses import dataclass

from scanner.core.models import TargetReport
from scanner.reporting.vapt import build_vapt_report


@dataclass(frozen=True)
class ExecutiveReport:
    summary: str
    posture: str
    top_risks: tuple[str, ...]
    attack_surface: tuple[str, ...]
    remediation_roadmap: tuple[str, ...]


def build_executive_report(reports: list[TargetReport]) -> ExecutiveReport:
    report = build_vapt_report(reports, audience="external")
    findings = [item for group in report.finding_groups.values() for item in group]
    top_risks = tuple(
        f"{item.source.title}: {item.risk_summary}"
        for item in sorted(findings, key=lambda value: value.source.risk_score, reverse=True)[:5]
    ) or ("No high-priority risks were identified by configured checks.",)
    attack_surface = tuple(f"{key.replace('_', ' ').title()}: {value}" for key, value in report.attack_surface.items())
    return ExecutiveReport(
        summary=report.executive_summary,
        posture=report.business_risk_summary,
        top_risks=top_risks,
        attack_surface=attack_surface,
        remediation_roadmap=report.remediation_roadmap,
    )


def render_executive_markdown(reports: list[TargetReport]) -> str:
    report = build_executive_report(reports)
    lines = [
        "# Executive Security Assessment",
        "",
        "## Executive Summary",
        "",
        report.summary,
        "",
        "## Security Posture",
        "",
        report.posture,
        "",
        "## Top Risks",
        "",
    ]
    lines.extend(f"- {risk}" for risk in report.top_risks)
    lines.extend(["", "## Attack Surface Overview", ""])
    lines.extend(f"- {item}" for item in report.attack_surface)
    lines.extend(["", "## Remediation Roadmap", ""])
    lines.extend(f"- {item}" for item in report.remediation_roadmap)
    return "\n".join(lines) + "\n"
