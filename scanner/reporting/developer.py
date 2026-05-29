from __future__ import annotations

from scanner.core.models import TargetReport
from scanner.remediation.engine import remediation_for
from scanner.reporting.evidence import lineage_for
from scanner.reporting.explanations import explain_finding


def render_developer_markdown(reports: list[TargetReport]) -> str:
    lines = ["# Developer Remediation Guide", ""]
    for report in reports:
        lines.extend([f"## Target: {report.input_url}", ""])
        if not report.findings:
            lines.extend(["No findings require developer remediation for configured checks.", ""])
            continue
        for finding in report.findings:
            explanation = explain_finding(finding)
            advice = remediation_for(finding, report)
            lineage = lineage_for(finding, report)
            lines.extend(
                [
                    f"### {finding.title}",
                    "",
                    f"- Severity: {finding.severity.value}",
                    f"- Confidence: {finding.confidence.value}",
                    f"- Affected: {explanation.affected_systems}",
                    f"- Why it matters: {explanation.why_it_matters}",
                    f"- Reproduction context: observe `{lineage.request_url}` with the configured non-invasive scanner request.",
                    f"- Remediation: {advice.summary}",
                ]
            )
            if advice.snippets:
                lines.append("- Implementation snippets:")
                for name, snippet in advice.snippets.items():
                    lines.extend([f"  - {name}", "```", snippet, "```"])
            lines.append("")
    return "\n".join(lines)
