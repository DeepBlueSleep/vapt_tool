from __future__ import annotations

import re
import urllib.parse

from scanner.checks.common import make_finding
from scanner.core.models import Classification, Confidence, Finding, FindingScope, Page, Reference, Severity
from scanner.plugins.base import PluginMetadata

SECURITY_HEADERS = {
    "strict-transport-security": (
        "Missing HTTP Strict Transport Security",
        Severity.HIGH,
        "Add Strict-Transport-Security on HTTPS responses.",
    ),
    "content-security-policy": ("Missing Content Security Policy", Severity.MEDIUM, "Add a restrictive Content-Security-Policy header."),
    "x-content-type-options": ("Missing X-Content-Type-Options", Severity.MEDIUM, "Set X-Content-Type-Options: nosniff."),
    "referrer-policy": ("Missing Referrer-Policy", Severity.LOW, "Set a privacy-preserving Referrer-Policy."),
    "permissions-policy": ("Missing Permissions-Policy", Severity.LOW, "Restrict browser features with Permissions-Policy."),
}


def first_header(headers: dict[str, list[str]], name: str) -> str | None:
    values = headers.get(name.lower())
    return values[0] if values else None


class HeaderCheck:
    metadata = PluginMetadata(
        name="passive.headers",
        version="1.0",
        description="Checks security response headers and CSP posture.",
        category="passive",
    )

    async def analyze(self, page: Page, _report: object) -> list[Finding]:
        findings: list[Finding] = []
        if urllib.parse.urlparse(page.final_url).scheme == "https":
            for header, (title, severity, remediation) in SECURITY_HEADERS.items():
                if header not in page.headers:
                    findings.append(
                        make_finding(
                            check=self.metadata.name,
                            url=page.final_url,
                            title=title,
                            severity=severity,
                            classification=Classification.RECOMMENDATION,
                            confidence=Confidence.HIGH,
                            evidence=f"{header} header was not present.",
                            remediation=remediation,
                            scope=FindingScope.HOST,
                        )
                    )
        csp = first_header(page.headers, "content-security-policy")
        if csp:
            risky_tokens = [token for token in ("'unsafe-inline'", "'unsafe-eval'", "*") if token in csp]
            if risky_tokens:
                findings.append(
                    make_finding(
                        check=self.metadata.name,
                        url=page.final_url,
                        title="Content Security Policy allows risky sources",
                        severity=Severity.MEDIUM,
                        classification=Classification.WEAKNESS,
                        confidence=Confidence.HIGH,
                        evidence="Risky CSP tokens: " + ", ".join(risky_tokens),
                        remediation="Remove unsafe CSP tokens where possible and use nonces, hashes, and specific source allowlists.",
                        scope=FindingScope.HOST,
                        references=[Reference("MDN CSP", "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP")],
                    )
                )
            if "frame-ancestors" not in csp:
                findings.append(
                    make_finding(
                        check=self.metadata.name,
                        url=page.final_url,
                        title="CSP is missing frame-ancestors",
                        severity=Severity.LOW,
                        classification=Classification.RECOMMENDATION,
                        confidence=Confidence.HIGH,
                        evidence="Content-Security-Policy did not include frame-ancestors.",
                        remediation="Add frame-ancestors to control which origins can frame the application.",
                        scope=FindingScope.HOST,
                    )
                )
        return findings


class CookieCheck:
    metadata = PluginMetadata(
        name="passive.cookies",
        version="1.0",
        description="Checks cookie security attributes.",
        category="passive",
    )

    async def analyze(self, page: Page, _report: object) -> list[Finding]:
        findings: list[Finding] = []
        for cookie in page.headers.get("set-cookie", []):
            lower = cookie.lower()
            missing = [flag for flag in ("secure", "httponly", "samesite") if flag not in lower]
            if missing:
                findings.append(
                    make_finding(
                        check=self.metadata.name,
                        url=page.final_url,
                        title="Cookie is missing recommended security attributes",
                        severity=Severity.MEDIUM if "secure" in missing else Severity.LOW,
                        classification=Classification.WEAKNESS,
                        confidence=Confidence.HIGH,
                        evidence="Missing attributes: " + ", ".join(missing),
                        remediation="Set Secure, HttpOnly, and SameSite attributes on sensitive cookies.",
                        scope=FindingScope.ENDPOINT,
                    )
                )
        return findings


class HtmlPassiveCheck:
    metadata = PluginMetadata(
        name="passive.html",
        version="1.0",
        description="Checks forms, mixed content, and directory listing markers.",
        category="passive",
    )

    async def analyze(self, page: Page, _report: object) -> list[Finding]:
        findings: list[Finding] = []
        if urllib.parse.urlparse(page.final_url).scheme == "https":
            insecure = [url for url in (*page.assets, *page.scripts) if url.startswith("http://")][:5]
            if insecure:
                findings.append(
                    make_finding(
                        check=self.metadata.name,
                        url=page.final_url,
                        title="Mixed content references found",
                        severity=Severity.MEDIUM,
                        classification=Classification.WEAKNESS,
                        confidence=Confidence.HIGH,
                        evidence="Examples: " + ", ".join(insecure),
                        remediation="Load all subresources over HTTPS.",
                        scope=FindingScope.ENDPOINT,
                    )
                )
        for form in page.forms:
            if form.has_password and not form.action.startswith("https://"):
                findings.append(
                    make_finding(
                        check=self.metadata.name,
                        url=page.final_url,
                        title="Password form submits without HTTPS",
                        severity=Severity.HIGH,
                        classification=Classification.VULNERABILITY,
                        confidence=Confidence.HIGH,
                        evidence=f"Form action is {form.action}.",
                        remediation="Serve and submit all authentication forms over HTTPS.",
                        scope=FindingScope.ENDPOINT,
                    )
                )
        text = page.body[:20_000].decode("utf-8", "ignore")
        if re.search(r"<title>\s*Index of /", text, re.I) or "Parent Directory" in text:
            findings.append(
                make_finding(
                    check=self.metadata.name,
                    url=page.final_url,
                    title="Directory listing appears enabled",
                    severity=Severity.MEDIUM,
                    classification=Classification.WEAKNESS,
                    confidence=Confidence.MEDIUM,
                    evidence="Directory index markers were present in the HTML response.",
                    remediation="Disable directory indexes for web-accessible directories.",
                    scope=FindingScope.PATH,
                )
            )
        return findings
