from __future__ import annotations

from dataclasses import dataclass

from scanner.core.models import Confidence, Finding, FindingScope


@dataclass(frozen=True)
class FindingExplanation:
    observed: str
    why_it_matters: str
    realistic_impact: str
    exploitability_context: str
    affected_systems: str
    confidence_rationale: str
    remediation_rationale: str


def explain_finding(finding: Finding) -> FindingExplanation:
    title = finding.title.lower()
    observed = _observed(finding)
    why = _why_it_matters(title, finding.scope)
    impact = _impact(title)
    exploitability = _exploitability(finding)
    affected = _affected(finding)
    confidence = _confidence(finding)
    remediation = _remediation_rationale(title)
    return FindingExplanation(
        observed=observed,
        why_it_matters=why,
        realistic_impact=impact,
        exploitability_context=exploitability,
        affected_systems=affected,
        confidence_rationale=confidence,
        remediation_rationale=remediation,
    )


def _observed(finding: Finding) -> str:
    count_text = f" across {finding.occurrence_count} observed resources" if finding.occurrence_count > 1 else ""
    evidence = "; ".join(finding.evidence_items[:3] or [finding.evidence])
    return f"{finding.title} was observed{count_text}. Evidence sample: {evidence}"


def _why_it_matters(title: str, scope: FindingScope) -> str:
    if "content security policy" in title or "csp" in title:
        return "Client-side injection protections are weaker when browser script execution policy is missing or permissive."
    if "strict transport security" in title or "hsts" in title:
        return "Transport downgrade and first-visit risks are higher when browsers are not instructed to require HTTPS for the host."
    if "cookie" in title:
        return "Session and preference cookies become easier to expose or misuse when browser-enforced cookie controls are absent."
    if "reflected" in title:
        return (
            "Reflected input increases the need for context-aware output encoding and may become higher risk "
            "if unsafe rendering paths exist."
        )
    if "graphql" in title:
        return "GraphQL endpoints often expose broad data access through a single route and need explicit production hardening."
    return f"The issue affects the {scope.value} attack surface and may increase application exposure if combined with other weaknesses."


def _impact(title: str) -> str:
    if "diagnostic" in title or "debug" in title:
        return "Internal implementation details may help attackers understand application behavior or data models."
    if "open redirect" in title:
        return "Users may be redirected to untrusted destinations, which can support phishing or trust-boundary confusion."
    if "dangerous http methods" in title:
        return "Unexpected methods increase the chance that infrastructure or application behavior diverges from intended access patterns."
    return (
        "The most realistic impact is risk amplification: the finding may not be directly exploitable alone, "
        "but it weakens defensive depth."
    )


def _exploitability(finding: Finding) -> str:
    if finding.confidence == Confidence.HIGH:
        return "The scanner has direct evidence for this condition. No exploit attempt was performed."
    if finding.confidence == Confidence.MEDIUM:
        return "The scanner observed a strong heuristic signal. Manual validation is recommended before treating it as confirmed."
    return "The scanner observed a weak heuristic signal. Treat this as a triage candidate."


def _affected(finding: Finding) -> str:
    affected = finding.affected_resources[:5] or [finding.url]
    suffix = " and additional resources" if finding.occurrence_count > len(affected) else ""
    return ", ".join(affected) + suffix


def _confidence(finding: Finding) -> str:
    return f"Confidence is {finding.confidence.value} because the check source was {finding.check} and scope was {finding.scope.value}."


def _remediation_rationale(title: str) -> str:
    if "missing" in title:
        return "Adding the missing control is typically a high-value hardening step with limited application behavior impact."
    if "reflected" in title:
        return "Fixes should focus on validation and output encoding in the specific rendering context, not generic filtering."
    return "Prioritize the fix according to risk, affected resources, and whether the behavior is exposed to untrusted users."
