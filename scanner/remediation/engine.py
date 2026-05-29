from __future__ import annotations

from dataclasses import dataclass, field

from scanner.core.models import Finding, TargetReport


@dataclass(frozen=True)
class RemediationAdvice:
    summary: str
    priority: str
    quick_wins: tuple[str, ...] = ()
    long_term: tuple[str, ...] = ()
    snippets: dict[str, str] = field(default_factory=dict)


def remediation_for(finding: Finding, report: TargetReport) -> RemediationAdvice:
    title = finding.title.lower()
    technologies = {key.lower(): value.lower() for key, value in report.technologies.items()}
    if "strict transport security" in title:
        return RemediationAdvice(
            summary="Enable HSTS on HTTPS responses once all subdomains and dependencies are HTTPS-ready.",
            priority="quick_win",
            quick_wins=("Set Strict-Transport-Security with a staged max-age.", "Confirm HTTP redirects always land on HTTPS."),
            long_term=("Consider includeSubDomains and preload after validation.",),
            snippets={
                "nginx": "add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;",
                "apache": "Header always set Strict-Transport-Security \"max-age=31536000; includeSubDomains\"",
            },
        )
    if "content security policy" in title or "csp" in title:
        return RemediationAdvice(
            summary="Deploy a restrictive CSP that matches the application's framework and script-loading model.",
            priority="planned_fix",
            quick_wins=("Start with report-only mode.", "Remove wildcard and unsafe sources where feasible."),
            long_term=("Adopt nonces or hashes for inline scripts.", "Monitor CSP reports before enforcement."),
            snippets={
                "nginx": "add_header Content-Security-Policy \"default-src 'self'; object-src 'none'; frame-ancestors 'none'\" always;",
                "react_next": "Use a nonce-aware CSP in middleware or next.config.js headers().",
            },
        )
    if "cookie" in title:
        return RemediationAdvice(
            summary="Set browser-enforced security attributes on cookies that carry session or sensitive state.",
            priority="quick_win",
            quick_wins=("Set Secure and HttpOnly on session cookies.", "Use SameSite=Lax or Strict unless cross-site flows require None."),
            snippets={
                "express": "res.cookie('sid', value, { httpOnly: true, secure: true, sameSite: 'lax' });",
                "django": "SESSION_COOKIE_SECURE=True\nSESSION_COOKIE_HTTPONLY=True\nSESSION_COOKIE_SAMESITE='Lax'",
            },
        )
    if "graphql" in title:
        return RemediationAdvice(
            summary="Confirm GraphQL endpoints enforce authentication, authorization, rate limits, and production-safe errors.",
            priority="planned_fix",
            quick_wins=("Disable introspection in production unless explicitly needed.", "Limit query depth and complexity."),
            long_term=("Add field-level authorization tests.", "Monitor rejected and expensive query patterns."),
        )
    if "reflected" in title:
        return RemediationAdvice(
            summary="Apply context-aware output encoding and validate reflected parameters at the boundary.",
            priority="triage",
            quick_wins=("Identify the rendering context from the evidence.", "Add regression tests for the affected parameter."),
            long_term=("Centralize encoding helpers for HTML, attributes, JavaScript, and JSON contexts.",),
        )
    framework_hint = "Next.js/React" if any("next" in key or "react" in key for key in technologies) else "application framework"
    return RemediationAdvice(
        summary=f"Review and remediate this finding in the relevant {framework_hint} layer.",
        priority="triage",
        quick_wins=(finding.remediation,),
        long_term=("Add a regression check to prevent recurrence.",),
    )
