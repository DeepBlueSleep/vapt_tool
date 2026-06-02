from __future__ import annotations

# The renderer intentionally keeps some HTML/CSS fragments as single strings so
# the generated template remains easy to scan alongside its composition code.
# ruff: noqa: E501
import datetime as dt
import html
import urllib.parse
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Any

from scanner.core.models import Finding, ScanResult, Severity, TargetReport
from scanner.remediation.engine import remediation_for
from scanner.reporting.attack_surface import summarize_all
from scanner.reporting.compliance import map_finding
from scanner.reporting.evidence import lineage_for
from scanner.reporting.explanations import explain_finding
from scanner.risk.correlation import correlated_risk_score
from scanner.risk.posture import score_posture

SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")
INFRA_TOKENS = ("header", "hsts", "tls", "cookie", "cors", "server", "directory", "exposed file", "cache")
APP_TOKENS = ("api", "graphql", "parameter", "reflected", "route", "auth", "session", "token", "form", "redirect", "runtime")


@dataclass(frozen=True)
class ReportFinding:
    source: Finding
    target: TargetReport
    category: str
    risk_summary: str
    technical_description: str
    business_impact: str
    affected_assets: tuple[str, ...]
    evidence: tuple[str, ...]
    steps_to_reproduce: tuple[str, ...]
    runtime_observations: tuple[str, ...]
    attack_scenarios: tuple[str, ...]
    remediation_steps: tuple[str, ...]
    implementation_examples: dict[str, str]
    validation_guidance: tuple[str, ...]
    cvss: str
    cwe: str
    references: tuple[str, ...]


@dataclass(frozen=True)
class ReportSection:
    title: str
    body: str
    items: tuple[str, ...] = ()


@dataclass(frozen=True)
class VaptReport:
    title: str
    audience: str
    generated_at_utc: str
    targets: tuple[TargetReport, ...]
    executive_summary: str
    key_observations: tuple[str, ...]
    business_risk_summary: str
    severity_counts: dict[str, int]
    finding_groups: dict[str, tuple[ReportFinding, ...]]
    attack_surface: dict[str, int]
    runtime_summary: ReportSection
    remediation_roadmap: tuple[str, ...]
    distribution: tuple[str, ...] = ("Client security owner", "Application owner", "Remediation teams")


def build_vapt_report(targets: list[TargetReport], audience: str = "internal", generated_at_utc: str | None = None) -> VaptReport:
    generated = generated_at_utc or dt.datetime.now(dt.UTC).isoformat()
    report_findings = [_professionalize_finding(target, finding, audience) for target in targets for finding in target.findings]
    grouped: dict[str, list[ReportFinding]] = defaultdict(list)
    for finding in sorted(report_findings, key=lambda item: correlated_risk_score(item.source), reverse=True):
        grouped[finding.category].append(finding)
    severity_counts = {severity: 0 for severity in SEVERITY_ORDER}
    for finding in report_findings:
        severity_counts[finding.source.severity.value] = severity_counts.get(finding.source.severity.value, 0) + 1
    surface = {key: int(value) for key, value in summarize_all(targets).items()}
    executive_summary, business_summary = _executive_narrative(targets, report_findings, surface, audience)
    return VaptReport(
        title="External Security Assessment" if audience == "external" else "Internal Remediation Report",
        audience=audience,
        generated_at_utc=generated,
        targets=tuple(targets),
        executive_summary=executive_summary,
        key_observations=_key_observations(targets, report_findings, surface),
        business_risk_summary=business_summary,
        severity_counts=severity_counts,
        finding_groups={key: tuple(value) for key, value in grouped.items()},
        attack_surface=surface,
        runtime_summary=_runtime_summary(targets),
        remediation_roadmap=_roadmap(report_findings),
    )


def render_vapt_html(result: ScanResult, audience: str = "internal") -> str:
    report = build_vapt_report(result.targets, audience=audience, generated_at_utc=result.generated_at_utc)
    return render_vapt_report_html(report)


def render_vapt_report_html(report: VaptReport) -> str:
    figures = _FigureCounter()
    body = [
        _cover(report),
        _toc(report),
        _simple_section("Distribution List", "This report is intended for authorized business, security, and engineering stakeholders.", report.distribution),
        _simple_section(
            "Disclaimer",
            "The assessment reflects observations available during the configured scan window. Findings should be validated in the target environment before production changes are applied.",
        ),
        _engagement(report),
        _methodology(),
        _executive(report),
        _severity_overview(report),
        _attack_surface(report, figures),
        _findings_summary(report),
        _finding_sections(report, figures),
        _runtime_analysis(report, figures),
        _appendices(report),
    ]
    return _page(report.title, "".join(body))


def render_vapt_markdown(report: VaptReport) -> str:
    lines = [
        f"# {report.title}",
        "",
        f"Generated: {report.generated_at_utc}",
        f"Audience: {report.audience}",
        "",
        "## Engagement Overview",
        "",
        report.executive_summary,
        "",
        "## Key Observations",
        "",
    ]
    lines.extend(f"- {item}" for item in report.key_observations)
    lines.extend(["", "## Severity Overview", "", "| Severity | Count |", "| --- | ---: |"])
    lines.extend(f"| {severity.title()} | {report.severity_counts.get(severity, 0)} |" for severity in SEVERITY_ORDER)
    lines.extend(["", "## Attack Surface Summary", ""])
    lines.extend(f"- {key.replace('_', ' ').title()}: {value}" for key, value in report.attack_surface.items())
    lines.extend(["", "## Findings Summary", ""])
    for category, findings in report.finding_groups.items():
        lines.extend([f"### {category}", ""])
        for item in findings:
            lines.append(f"- {item.source.severity.value.title()}: {item.source.title} ({item.source.occurrence_count} occurrence(s))")
        lines.append("")
    lines.extend(["## Detailed Findings", ""])
    for category, findings in report.finding_groups.items():
        lines.extend([f"### {category}", ""])
        for item in findings:
            lines.extend(_finding_markdown(item, include_internal=report.audience != "external"))
    if report.audience == "external":
        lines.extend(["", "Detailed implementation guidance is intentionally excluded from the external report."])
    return "\n".join(lines) + "\n"


def vapt_json_payload(report: VaptReport, include_internal: bool) -> dict[str, Any]:
    findings = [item for group in report.finding_groups.values() for item in group]
    return {
        "title": report.title,
        "audience": report.audience,
        "generated_at_utc": report.generated_at_utc,
        "executive_summary": report.executive_summary,
        "key_observations": list(report.key_observations),
        "severity_counts": report.severity_counts,
        "attack_surface": report.attack_surface,
        "runtime_summary": {"title": report.runtime_summary.title, "body": report.runtime_summary.body, "items": list(report.runtime_summary.items)},
        "findings": [
            {
                "title": item.source.title,
                "severity": item.source.severity.value,
                "category": item.category,
                "risk_summary": item.risk_summary,
                "business_impact": item.business_impact,
                "affected_assets": list(item.affected_assets),
                "evidence": list(item.evidence) if include_internal else [_truncate(value, 220) for value in item.evidence[:2]],
                "remediation": list(item.remediation_steps) if include_internal else [],
                "cvss": item.cvss,
                "cwe": item.cwe,
            }
            for item in findings
        ],
    }


def _professionalize_finding(target: TargetReport, finding: Finding, audience: str) -> ReportFinding:
    explanation = explain_finding(finding)
    advice = remediation_for(finding, target)
    lineage = lineage_for(finding, target)
    mapping = map_finding(finding)
    affected = tuple(dict.fromkeys(finding.affected_resources or [finding.url]))
    samples = affected[:5]
    scope_word = "application" if _category_for(finding) == "Application Security Findings" else "environment"
    risk_summary = _risk_summary(finding, samples)
    technical = _technical_description(finding, explanation.observed, affected)
    impact = _business_impact(finding, target)
    evidence = tuple(dict.fromkeys((finding.evidence_items or [finding.evidence]) + [lineage.response_summary]))[:6]
    runtime = tuple(dict.fromkeys((*lineage.discovery_path, *lineage.browser_evidence[:3], *target.inventory.get("runtime_apis", [])[:3])))
    remediation = (*advice.quick_wins, *advice.long_term)
    if not remediation:
        remediation = (advice.summary,)
    if audience == "external":
        remediation = (advice.summary, "Coordinate implementation details with the application and infrastructure owners.")
        evidence = tuple(_truncate(item, 220) for item in evidence[:3])
    return ReportFinding(
        source=finding,
        target=target,
        category=_category_for(finding),
        risk_summary=risk_summary,
        technical_description=technical,
        business_impact=impact,
        affected_assets=samples,
        evidence=evidence,
        steps_to_reproduce=_steps_to_reproduce(finding),
        runtime_observations=runtime or ("No browser runtime evidence was associated with this finding.",),
        attack_scenarios=_attack_scenarios(finding, scope_word),
        remediation_steps=remediation,
        implementation_examples=advice.snippets,
        validation_guidance=_validation_guidance(finding),
        cvss=str(finding.metadata.get("cvss", _cvss_hint(finding))),
        cwe=", ".join(mapping.cwe[:2]) if mapping.cwe else str(finding.metadata.get("cwe", "CWE mapping not assigned")),
        references=tuple(reference.url for reference in finding.references),
    )


def _executive_narrative(
    targets: list[TargetReport],
    findings: list[ReportFinding],
    surface: dict[str, int],
    audience: str,
) -> tuple[str, str]:
    grades = [score_posture(target).grade for target in targets]
    critical_high = sum(1 for item in findings if item.source.severity in {Severity.CRITICAL, Severity.HIGH})
    runtime = surface.get("runtime_apis", 0)
    auth = surface.get("auth_routes", 0)
    frameworks = sorted({key.split(":", 1)[-1] for target in targets for key in target.technologies if "framework" in key.lower()})
    posture = _posture_phrase(grades, critical_high)
    complexity = _complexity_phrase(surface, frameworks)
    runtime_sentence = (
        f"Browser-assisted analysis observed {runtime} runtime API surface(s) and {auth} authentication signal(s), "
        "which provides useful context for remediation sequencing."
        if runtime or auth
        else "The assessment did not record significant browser runtime API exposure, so residual risk is primarily based on passive and crawler-observed behavior."
    )
    summary = (
        f"The assessment covered {len(targets)} target(s) and indicates a {posture}. "
        f"{complexity} {runtime_sentence} "
        "The report prioritizes issues by exploitability, exposure breadth, and operational remediation value rather than raw scanner volume."
    )
    if audience == "external":
        summary += " Sensitive exploit detail has been reduced for external distribution."
    business = (
        "The main business concern is the combination of externally reachable functionality, browser-discovered behavior, and recurring control gaps. "
        "These conditions can increase the likelihood of unauthorized data exposure, client-side abuse, or avoidable operational disruption if left unmanaged."
        if critical_high or runtime or surface.get("apis", 0)
        else "Observed risk is currently limited, but routine hardening and validation should continue so low-severity weaknesses do not become durable control gaps."
    )
    return summary, business


def _key_observations(targets: list[TargetReport], findings: list[ReportFinding], surface: dict[str, int]) -> tuple[str, ...]:
    observations = [
        f"{surface.get('pages', 0)} page(s), {surface.get('apis', 0)} static API indicator(s), and {surface.get('runtime_apis', 0)} runtime API call(s) were catalogued.",
        f"{surface.get('forms', 0)} static form(s) and {surface.get('dynamic_forms', 0)} dynamic form(s) were observed across the assessed application surface.",
    ]
    if surface.get("auth_routes", 0):
        observations.append(f"Authentication-related routes or controls were detected in {surface['auth_routes']} location(s), increasing the need for workflow-aware validation.")
    repeated = [item for item in findings if item.source.occurrence_count > 1]
    if repeated:
        top = repeated[0]
        observations.append(
            f"{top.source.title} appeared across {top.source.occurrence_count} observed location(s), so remediation should be implemented centrally where possible."
        )
    tech = sorted({f"{key}={value}" for target in targets for key, value in target.technologies.items()})
    if tech:
        observations.append(f"Detected technology signals include {', '.join(tech[:5])}.")
    return tuple(observations)


def _runtime_summary(targets: list[TargetReport]) -> ReportSection:
    runtime_items = []
    for target in targets:
        runtime_items.extend(target.inventory.get("runtime_apis", [])[:30])
        runtime_items.extend(target.inventory.get("browser_routes", [])[:20])
        runtime_items.extend(target.inventory.get("runtime_parameters", [])[:20])
    if runtime_items:
        body = "Browser instrumentation identified dynamic routes, API calls, and parameter usage that may not be visible to a static crawler."
    else:
        body = "No dedicated runtime API traces were recorded for this scan. Static discovery and passive analysis remain represented in the findings."
    return ReportSection("Runtime/API Analysis", body, tuple(dict.fromkeys(runtime_items))[:60])


def _roadmap(findings: list[ReportFinding]) -> tuple[str, ...]:
    if not findings:
        return ("Maintain baseline monitoring and repeat assessment after major application releases.",)
    by_severity = Counter(item.source.severity.value for item in findings)
    roadmap = []
    if by_severity["critical"] or by_severity["high"]:
        roadmap.append("Within 7 days: remediate critical and high-risk issues, then validate fixes against representative affected routes.")
    roadmap.append("Within 30 days: centralize recurring control fixes such as security headers, cookie attributes, API authorization, and framework-level output handling.")
    roadmap.append("Within 60 days: add regression coverage for remediated findings and monitor runtime API exposure during release testing.")
    roadmap.append("Ongoing: review newly discovered browser routes, third-party integrations, and authentication workflows after each material application change.")
    return tuple(roadmap)


def _category_for(finding: Finding) -> str:
    text = f"{finding.title} {finding.url} {finding.check}".lower()
    if any(token in text for token in ("runtime", "graphql", "api", "websocket")):
        return "Runtime/API Analysis"
    if any(token in text for token in APP_TOKENS):
        return "Application Security Findings"
    if any(token in text for token in INFRA_TOKENS):
        return "Infrastructure Security Findings"
    return "Application Security Findings" if finding.scope.value in {"parameter", "endpoint"} else "Infrastructure Security Findings"


def _risk_summary(finding: Finding, affected: tuple[str, ...]) -> str:
    count = finding.occurrence_count
    target = _host(finding.url)
    if count > 1:
        return f"{finding.title} was observed consistently across {count} {finding.scope.value}-level location(s) on {target}, indicating a recurring control gap rather than an isolated endpoint issue."
    asset = affected[0] if affected else finding.url
    return f"{finding.title} was observed on {asset}. The issue should be reviewed in context of the affected workflow and exposed functionality."


def _technical_description(finding: Finding, observed: str, affected: tuple[str, ...]) -> str:
    if finding.occurrence_count > len(affected):
        return f"{observed} Representative evidence is shown for {len(affected)} sampled asset(s), with {finding.occurrence_count} total occurrence(s) tracked by the scanner."
    return observed


def _business_impact(finding: Finding, target: TargetReport) -> str:
    title = finding.title.lower()
    if "content security policy" in title or "reflected" in title:
        return "A successful attack could weaken client-side trust boundaries, increasing exposure to script injection, data theft, or user session abuse."
    if "cookie" in title or "session" in title or "auth" in title:
        return "Weak session or authentication controls can increase the likelihood of account misuse, privilege confusion, or unauthorized access to protected workflows."
    if "api" in title or target.inventory.get("runtime_apis"):
        return "API exposure can increase the volume of reachable business logic and data-processing paths that require authorization, validation, and monitoring."
    if finding.severity in {Severity.CRITICAL, Severity.HIGH}:
        return "The issue may materially affect confidentiality, integrity, or availability if reachable by an external attacker."
    return "The issue contributes to defense-in-depth weakness and should be remediated as part of routine hardening."


def _steps_to_reproduce(finding: Finding) -> tuple[str, ...]:
    return (
        f"Access the representative affected asset: {finding.url}.",
        "Review the HTTP response, browser behavior, or runtime trace associated with the evidence.",
        f"Confirm that the observed condition matches the finding: {finding.title}.",
    )


def _attack_scenarios(finding: Finding, scope_word: str) -> tuple[str, ...]:
    title = finding.title.lower()
    if "content security policy" in title:
        return ("An attacker who finds an injection path has fewer browser-enforced restrictions preventing malicious script execution.",)
    if "graphql" in title:
        return ("An attacker enumerates schema behavior or sends expensive queries to identify data exposure and operational limits.",)
    if "api" in title:
        return ("An attacker maps exposed API routes and probes authorization, validation, and error-handling differences.",)
    return (f"An attacker uses the exposed {scope_word} behavior as a stepping stone during reconnaissance or exploit chaining.",)


def _validation_guidance(finding: Finding) -> tuple[str, ...]:
    return (
        "Re-run the assessment against the affected target after remediation.",
        "Manually verify at least one representative sampled asset and one high-value workflow.",
        f"Confirm the finding no longer appears for deduplication key {finding.normalized_key()}.",
    )


def _cvss_hint(finding: Finding) -> str:
    return {
        Severity.CRITICAL: "9.1",
        Severity.HIGH: "8.0",
        Severity.MEDIUM: "5.3",
        Severity.LOW: "3.1",
        Severity.INFO: "0.0",
    }[finding.severity]


def _cover(report: VaptReport) -> str:
    target_label = ", ".join(target.input_url for target in report.targets[:3])
    return (
        "<section class='cover'>"
        "<div><p class='eyebrow'>Browser-Assisted Security Assessment</p>"
        f"<h1>{html.escape(report.title)}</h1>"
        "<p class='deck'>Security Assessment Dashboard</p>"
        f"<p class='lead'>{html.escape(target_label)}</p>"
        f"<p>{html.escape(_report_date(report.generated_at_utc))} | Confidential | {html.escape(report.audience.title())} report</p></div>"
        "<div class='cover-grid'>"
        f"<span><b>{len(report.targets)}</b>Targets</span><span><b>{sum(report.severity_counts.values())}</b>Findings</span>"
        f"<span><b>{report.attack_surface.get('runtime_apis', 0)}</b>Runtime APIs</span><span><b>{report.attack_surface.get('auth_routes', 0)}</b>Auth Signals</span>"
        "</div></section>"
    )


def _toc(report: VaptReport) -> str:
    finding_sections = tuple(
        category
        for category in ("Application Security Findings", "Infrastructure Security Findings", "Runtime/API Analysis")
        if report.finding_groups.get(category)
    )
    sections = (
        "Distribution List",
        "Disclaimer",
        "Engagement Overview",
        "Scope",
        "Methodology",
        "Executive Summary",
        "Key Observations",
        "Severity Overview",
        "Attack Surface Summary",
        "Findings Summary Table",
        "Detailed Findings",
        *finding_sections,
        "Appendices",
        "CVSS Methodology",
        "CWE Reference",
        "OWASP Risk Methodology",
    )
    return _simple_section("Table of Contents", "Report sections included in this deliverable.", sections)


def _engagement(report: VaptReport) -> str:
    targets = tuple(target.input_url for target in report.targets)
    return _simple_section(
        "Engagement Overview",
        "The assessment used crawler, passive analysis, safe active checks where configured, and browser runtime instrumentation to characterize externally reachable web application risk.",
        targets,
    ) + _simple_section("Scope", "In-scope targets for this automated deliverable.", targets)


def _methodology() -> str:
    return _simple_section(
        "Methodology",
        "Testing prioritized safe, non-destructive techniques suitable for authorized defensive assessment.",
        (
            "Crawl and sitemap-based route discovery",
            "Passive HTTP response, header, cookie, and technology review",
            "Browser-assisted SPA, route, network, and runtime API observation",
            "Finding correlation, aggregation, and risk-based prioritization",
            "Framework-aware remediation guidance and validation planning",
        ),
    )


def _executive(report: VaptReport) -> str:
    observations = "".join(f"<li>{html.escape(item)}</li>" for item in report.key_observations)
    return (
        "<section><h2>Executive Summary</h2>"
        f"<p class='narrative'>{html.escape(report.executive_summary)}</p>"
        f"<p>{html.escape(report.business_risk_summary)}</p>"
        "<h3>Key Observations</h3><ul class='checklist'>"
        f"{observations}</ul></section>"
    )


def _severity_overview(report: VaptReport) -> str:
    cards = "".join(
        f"<article class='metric sev-{severity}'><span>{severity.title()}</span><b>{report.severity_counts.get(severity, 0)}</b></article>"
        for severity in SEVERITY_ORDER
    )
    total = max(1, sum(report.severity_counts.values()))
    heat = "".join(
        f"<span class='heat sev-{severity}' style='width:{(report.severity_counts.get(severity, 0) / total) * 100:.1f}%'></span>"
        for severity in SEVERITY_ORDER
        if report.severity_counts.get(severity, 0)
    )
    return f"<section><h2>Severity Overview</h2><div class='metrics'>{cards}</div><div class='heatmap'>{heat}</div></section>"


def _attack_surface(report: VaptReport, figures: _FigureCounter) -> str:
    labels = {
        "expanded": "Expanded candidates",
        "verified_expanded": "Verified expanded",
    }
    cards = "".join(
        f"<article class='metric'><span>{html.escape(labels.get(key, key.replace('_', ' ').title()))}</span><b>{value}</b></article>"
        for key, value in report.attack_surface.items()
    )
    caption = figures.next("Attack surface metrics summarize crawl, browser runtime, authentication, and API discovery signals.")
    definitions = (
        "<dl class='definitions'>"
        "<dt>Expanded candidates</dt><dd>Potential routes, APIs, files, or framework paths inferred from observed application behavior and technology signals. These are leads for review, not confirmed vulnerabilities.</dd>"
        "<dt>Verified expanded</dt><dd>Expanded candidates that responded during safe probing or were otherwise confirmed as reachable during the assessment.</dd>"
        "</dl>"
    )
    return f"<section><h2>Attack Surface Summary</h2><div class='metrics'>{cards}</div>{definitions}<p class='caption'>{html.escape(caption)}</p></section>"


def _findings_summary(report: VaptReport) -> str:
    rows = []
    for category, findings in report.finding_groups.items():
        for item in findings:
            rows.append(
                "<tr><td><span class='badge sev-{severity}'>{severity}</span></td><td>{category}</td><td>{title}</td>"
                "<td>{count}</td><td>{risk}</td></tr>".format(
                    severity=html.escape(item.source.severity.value),
                    category=html.escape(category),
                    title=html.escape(item.source.title),
                    count=item.source.occurrence_count,
                    risk=correlated_risk_score(item.source),
                )
            )
    empty_row = '<tr><td colspan="5">No findings detected.</td></tr>'
    rendered_rows = "".join(rows) or empty_row
    return (
        "<section><h2>Findings Summary Table</h2><table><thead><tr><th>Severity</th><th>Category</th><th>Finding</th>"
        f"<th>Occurrences</th><th>Risk</th></tr></thead><tbody>{rendered_rows}</tbody></table></section>"
    )


def _finding_sections(report: VaptReport, figures: _FigureCounter) -> str:
    all_findings = [item for findings in report.finding_groups.values() for item in findings]
    if not all_findings:
        return "<section><h2>Detailed Findings</h2><p>No security findings were recorded for this assessment.</p></section>"
    output = [
        "<section><h2>Detailed Findings</h2>"
        "<p>The following sections contain only categories with recorded findings. Empty categories are intentionally omitted.</p>"
        f"<p>Total detailed findings: {len(all_findings)}.</p></section>"
    ]
    for category in ("Application Security Findings", "Infrastructure Security Findings", "Runtime/API Analysis"):
        findings = report.finding_groups.get(category, ())
        if not findings:
            continue
        output.append(f"<section><h2>{html.escape(category)}</h2>{''.join(_finding_card(item, figures, report.audience) for item in findings)}</section>")
    return "".join(output)


def _finding_card(item: ReportFinding, figures: _FigureCounter, audience: str) -> str:
    finding = item.source
    evidence = "".join(_evidence_card(value, figures) for value in item.evidence)
    assets = "".join(f"<li>{html.escape(asset)}</li>" for asset in item.affected_assets)
    steps = "".join(f"<li>{html.escape(step)}</li>" for step in item.steps_to_reproduce)
    runtime = "".join(f"<li>{html.escape(value)}</li>" for value in item.runtime_observations[:8])
    scenarios = "".join(f"<li>{html.escape(value)}</li>" for value in item.attack_scenarios)
    remediation = "".join(f"<li>{html.escape(step)}</li>" for step in item.remediation_steps)
    examples = "".join(
        f"<h5>{html.escape(name)}</h5><pre>{html.escape(snippet)}</pre>" for name, snippet in item.implementation_examples.items()
    )
    validation = "".join(f"<li>{html.escape(step)}</li>" for step in item.validation_guidance)
    sensitive = (
        ""
        if audience == "external"
        else f"<h4>Steps to Reproduce</h4><ol>{steps}</ol><h4>Runtime Observations</h4><ul>{runtime}</ul>"
        f"<h4>Implementation Example</h4>{examples or '<p>No framework-specific example was generated.</p>'}"
    )
    return (
        "<article class='finding-card'>"
        "<div class='finding-head'><div>"
        f"<p class='eyebrow'>{html.escape(item.category)}</p><h3>{html.escape(finding.title)}</h3></div>"
        f"<span class='badge sev-{finding.severity.value}'>{html.escape(finding.severity.value.title())}</span></div>"
        "<div class='meta'>"
        f"<span>CVSS {html.escape(item.cvss)}</span><span>{html.escape(item.cwe)}</span><span>{finding.occurrence_count} occurrence(s)</span>"
        "</div>"
        f"<h4>Risk Summary</h4><p>{html.escape(item.risk_summary)}</p>"
        f"<h4>Technical Description</h4><p>{html.escape(item.technical_description)}</p>"
        f"<h4>Business Impact</h4><p>{html.escape(item.business_impact)}</p>"
        f"<h4>Affected Assets</h4><ul>{assets or '<li>No affected asset sample recorded.</li>'}</ul>"
        f"<h4>Evidence</h4><div class='evidence-grid'>{evidence}</div>"
        f"{sensitive}"
        f"<h4>Attack Scenarios</h4><ul>{scenarios}</ul>"
        f"<h4>Recommended Remediation</h4><ul>{remediation}</ul>"
        f"<h4>Validation Guidance</h4><ul>{validation}</ul>"
        "</article>"
    )


def _runtime_analysis(report: VaptReport, figures: _FigureCounter) -> str:
    items = "".join(f"<li>{html.escape(item)}</li>" for item in report.runtime_summary.items[:40])
    caption = figures.next("Runtime intelligence is derived from browser-assisted network, route, form, and parameter observation.")
    return (
        f"<section><h2>{html.escape(report.runtime_summary.title)}</h2><p>{html.escape(report.runtime_summary.body)}</p>"
        f"<ul class='columns'>{items or '<li>No runtime items recorded.</li>'}</ul><p class='caption'>{html.escape(caption)}</p></section>"
    )


def _appendices(report: VaptReport) -> str:
    cwe_values = _cwe_values(report)
    cwe_items = "".join(
        f"<li><b>{html.escape(value)}</b>: {html.escape(_cwe_description(value))}</li>"
        for value in cwe_values
    )
    return (
        "<section class='appendix appendix-cover'><h2>Appendices</h2>"
        "<p>The following reference pages explain the scoring and weakness identifiers used throughout this report.</p>"
        "</section>"
        "<section class='appendix'><h2>Appendix A: CVSS Methodology</h2>"
        "<p>CVSS means Common Vulnerability Scoring System. It is an industry-standard way to describe vulnerability severity using a numeric score, commonly from 0.0 to 10.0.</p>"
        "<p>In this report, CVSS values are severity-aligned guidance when a scanner finding does not include a full formal vector. Manual validation should refine vectors before formal risk acceptance or contractual reporting.</p>"
        "<table><thead><tr><th>Score Range</th><th>Typical Rating</th><th>Meaning</th></tr></thead><tbody>"
        "<tr><td>9.0-10.0</td><td>Critical</td><td>Likely urgent business or technical risk requiring immediate action.</td></tr>"
        "<tr><td>7.0-8.9</td><td>High</td><td>Material risk that should be remediated in a near-term release or emergency window.</td></tr>"
        "<tr><td>4.0-6.9</td><td>Medium</td><td>Meaningful weakness that should be planned, tracked, and verified after remediation.</td></tr>"
        "<tr><td>0.1-3.9</td><td>Low</td><td>Defense-in-depth issue or limited exposure requiring routine hardening.</td></tr>"
        "</tbody></table></section>"
        "<section class='appendix'><h2>Appendix B: CWE Reference</h2>"
        "<p>CWE means Common Weakness Enumeration. A CWE identifier, such as CWE-79, names the underlying software weakness class behind a finding. It is not a proof of exploit by itself; it helps engineering teams find the right remediation pattern and track recurring weakness categories.</p>"
        f"<ul>{cwe_items or '<li>No specific CWE identifiers were assigned to this report.</li>'}</ul>"
        "<p>When a finding lists multiple CWE values, treat them as related weakness categories. The remediation should address the root control gap rather than only the individual URL or evidence sample.</p>"
        "</section>"
        "<section class='appendix'><h2>Appendix C: OWASP Risk Methodology</h2>"
        "<p>Findings are interpreted using likelihood, impact, exposure breadth, confidence, exploitability, and affected business workflow context.</p>"
        "<p>Automated results should be reviewed by application owners because scanner evidence may not always represent business-criticality, compensating controls, or authentication context.</p>"
        "</section>"
    )


def _evidence_card(value: str, figures: _FigureCounter) -> str:
    caption = figures.next("Representative evidence sample.")
    return f"<figure class='evidence-card'><pre>{html.escape(value)}</pre><figcaption>{html.escape(caption)}</figcaption></figure>"


def _finding_markdown(item: ReportFinding, include_internal: bool) -> list[str]:
    finding = item.source
    lines = [
        f"#### {finding.title}",
        "",
        f"- Severity: {finding.severity.value.title()}",
        f"- CVSS: {item.cvss}",
        f"- CWE: {item.cwe}",
        f"- Occurrences: {finding.occurrence_count}",
        "",
        "Risk Summary:",
        item.risk_summary,
        "",
        "Technical Description:",
        item.technical_description,
        "",
        "Business Impact:",
        item.business_impact,
        "",
        "Affected Assets:",
    ]
    lines.extend(f"- {asset}" for asset in item.affected_assets)
    lines.extend(["", "Evidence:"])
    lines.extend(f"- {evidence}" for evidence in item.evidence)
    if include_internal:
        lines.extend(["", "Steps to Reproduce:"])
        lines.extend(f"- {step}" for step in item.steps_to_reproduce)
        lines.extend(["", "Runtime Observations:"])
        lines.extend(f"- {value}" for value in item.runtime_observations)
    lines.extend(["", "Attack Scenarios:"])
    lines.extend(f"- {value}" for value in item.attack_scenarios)
    lines.extend(["", "Recommended Remediation:"])
    lines.extend(f"- {step}" for step in item.remediation_steps)
    if include_internal:
        lines.extend(["", "Implementation Example:"])
        if item.implementation_examples:
            for name, snippet in item.implementation_examples.items():
                lines.extend([f"{name}:", "```text", snippet, "```"])
        else:
            lines.append("No framework-specific example was generated.")
    lines.extend(["", "Validation Guidance:"])
    lines.extend(f"- {step}" for step in item.validation_guidance)
    lines.append("")
    return lines


def _simple_section(title: str, body: str, items: tuple[str, ...] = ()) -> str:
    rendered = "".join(f"<li>{html.escape(item)}</li>" for item in items)
    return f"<section><h2>{html.escape(title)}</h2><p>{html.escape(body)}</p>{f'<ul>{rendered}</ul>' if items else ''}</section>"


def _page(title: str, body: str) -> str:
    return (
        "<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>"
        f"<title>{html.escape(title)}</title><style>{_css()}</style></head><body>{body}</body></html>"
    )


def _css() -> str:
    return (
        "@page{size:A4;margin:16mm 16mm 20mm}*{box-sizing:border-box}body{margin:0;background:#fff;color:#17202c;font-family:Inter,Segoe UI,Arial,sans-serif;line-height:1.55;overflow-wrap:anywhere;word-break:normal}"
        "section{max-width:1120px;margin:0 auto 22px;background:#fff;border:0;border-radius:0;padding:0 0 14px;break-before:page;page-break-before:always;break-inside:auto;border-bottom:1px solid #e5e7eb}"
        "section:first-child{break-before:auto;page-break-before:auto}section:last-child{border-bottom:0}.appendix{min-height:920px;padding-top:8px}.appendix-cover{min-height:360px}"
        ".cover{min-height:82vh;display:grid;align-content:space-between;background:#fff;color:#17202c;border:0}.cover h1{font-size:48px;line-height:1.05;margin:8px 0 16px}"
        ".lead{font-size:20px;color:#334155}.eyebrow{text-transform:uppercase;font-size:12px;letter-spacing:.08em;color:#506174;font-weight:700}.cover .eyebrow{color:#0f766e}"
        ".cover-grid,.metrics{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px}.cover-grid span,.metric{border:1px solid #d8dee8;border-radius:8px;padding:14px;background:#f8fafc}"
        ".cover-grid span{background:rgba(255,255,255,.1);border-color:rgba(255,255,255,.25)}.cover-grid b,.metric b{display:block;font-size:30px}.metric span{color:#506174}"
        "h2{font-size:26px;margin:0 0 12px;color:#111827}h3{font-size:21px;margin:0 0 10px}h4{font-size:14px;margin:18px 0 6px;color:#1f2937;text-transform:uppercase}"
        ".narrative{font-size:18px}.checklist li,.roadmap li{margin:8px 0}.badge{display:inline-block;border-radius:999px;padding:4px 10px;font-size:12px;font-weight:700;text-transform:uppercase;white-space:nowrap;overflow-wrap:normal;word-break:keep-all}"
        ".sev-critical{background:#7f1d1d;color:#fff}.sev-high{background:#dc2626;color:#fff}.sev-medium{background:#f59e0b;color:#111827}.sev-low{background:#dbeafe;color:#1d4ed8}.sev-info{background:#e5e7eb;color:#374151}"
        ".heatmap{height:12px;display:flex;border-radius:999px;overflow:hidden;background:#e5e7eb;margin-top:12px}.heat{display:block;height:12px}"
        "table{width:100%;border-collapse:collapse;font-size:14px}th,td{border-bottom:1px solid #e5e7eb;padding:10px;text-align:left;vertical-align:top}th{color:#506174;background:#f8fafc}"
        ".finding-card{border:0;border-left:4px solid #0f766e;border-radius:0;padding:8px 0 8px 18px;margin:18px 0;background:#fff;break-inside:auto}.finding-head{display:flex;justify-content:space-between;gap:16px;align-items:flex-start}"
        ".meta{display:flex;flex-wrap:wrap;gap:8px;margin:8px 0 16px}.meta span{border:1px solid #d8dee8;border-radius:999px;padding:4px 10px;background:#f8fafc;color:#506174;font-size:12px;white-space:nowrap;overflow-wrap:normal;word-break:keep-all}"
        ".definitions{display:grid;grid-template-columns:170px 1fr;gap:8px 14px;margin:16px 0;padding:12px 0;border-top:1px solid #e5e7eb;border-bottom:1px solid #e5e7eb}.definitions dt{font-weight:800;color:#111827}.definitions dd{margin:0;color:#374151}"
        ".evidence-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:12px}.evidence-card{margin:0;border:1px solid #334155;border-radius:6px;overflow:hidden;background:#020617}"
        "pre{margin:0;padding:14px;white-space:pre-wrap;overflow-wrap:anywhere;word-break:break-word;color:#f8fafc;background:#020617;font:12px/1.5 Consolas,Menlo,monospace}.evidence-card figcaption,.caption{font-size:12px;color:#374151;padding:8px 0;background:#fff;margin:0}"
        "p,li,td,dd{overflow-wrap:anywhere}.columns{columns:2;overflow-wrap:anywhere}.appendix p,.appendix li{font-size:15px;line-height:1.7}.appendix table{margin-top:18px}"
        "@media(max-width:760px){section{border-radius:0;margin-bottom:10px}.cover h1{font-size:34px}.columns{columns:1}.finding-head{display:block}.definitions{grid-template-columns:1fr}}"
        "@media print{body{background:#fff}section{box-shadow:none;break-before:page;page-break-before:always}section:first-child{break-before:auto;page-break-before:auto}.cover{page-break-after:always}.finding-card{break-inside:auto}.badge,.meta span,td:first-child{white-space:nowrap;overflow-wrap:normal;word-break:keep-all}}"
    )


def _posture_phrase(grades: list[str], critical_high: int) -> str:
    if critical_high:
        return "risk posture requiring near-term remediation focus"
    if any(grade in {"D", "F"} for grade in grades):
        return "developing security posture with several hardening opportunities"
    if any(grade in {"A", "B"} for grade in grades):
        return "generally controlled posture with targeted improvement areas"
    return "moderate security posture with routine remediation needs"


def _complexity_phrase(surface: dict[str, int], frameworks: list[str]) -> str:
    total_dynamic = surface.get("runtime_apis", 0) + surface.get("dynamic_forms", 0) + surface.get("expanded", 0)
    framework = f" Detected framework signals include {', '.join(frameworks[:3])}." if frameworks else ""
    if total_dynamic >= 10:
        return f"The application presents a dynamic attack surface with meaningful client-side and API-driven behavior.{framework}"
    if surface.get("apis", 0) or surface.get("runtime_apis", 0):
        return f"The application exposes API-oriented functionality that should remain part of regression and authorization testing.{framework}"
    return f"The observed application surface is comparatively small based on the configured scan depth.{framework}"


def _host(url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    return parsed.netloc or url


def _report_date(value: str) -> str:
    try:
        return dt.datetime.fromisoformat(value.replace("Z", "+00:00")).date().isoformat()
    except ValueError:
        return value.split("T", 1)[0]


def _cwe_values(report: VaptReport) -> tuple[str, ...]:
    values: list[str] = []
    for findings in report.finding_groups.values():
        for item in findings:
            values.extend(part.strip() for part in item.cwe.split(",") if part.strip().startswith("CWE-"))
    return tuple(dict.fromkeys(values))


def _cwe_description(value: str) -> str:
    descriptions = {
        "CWE-79": "Improper neutralization of input during web page generation, commonly associated with cross-site scripting risk.",
        "CWE-209": "Generation of error messages containing sensitive information, which can disclose implementation detail to attackers.",
        "CWE-284": "Improper access control, where authorization or permission boundaries may not be enforced correctly.",
        "CWE-319": "Cleartext transmission of sensitive information over a channel that should be protected.",
        "CWE-614": "Sensitive cookie in an HTTPS session without the Secure attribute, increasing exposure if transport is downgraded or mishandled.",
    }
    return descriptions.get(value, "Common Weakness Enumeration category referenced by this finding. Use the CWE identifier to look up the weakness class and recommended mitigation pattern.")


def _truncate(value: str, limit: int) -> str:
    return value if len(value) <= limit else value[: limit - 3] + "..."


@dataclass
class _FigureCounter:
    value: int = field(default=0)

    def next(self, caption: str) -> str:
        self.value += 1
        return f"Figure {self.value}. {caption}"
