from __future__ import annotations

import re
import urllib.parse

from scanner.checks.common import make_finding
from scanner.core.models import Classification, Confidence, Finding, FindingScope, Page, Reference, Severity
from scanner.plugins.base import PluginMetadata
from scanner.checks.policies import parse_csp, script_policy_risks

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
            risky_tokens = script_policy_risks(page.headers.get("content-security-policy", []))
            if risky_tokens:
                findings.append(
                    make_finding(
                        check=self.metadata.name,
                        url=page.final_url,
                        title="Content Security Policy allows risky sources",
                        severity=Severity.MEDIUM,
                        classification=Classification.WEAKNESS,
                        confidence=Confidence.HIGH,
                        evidence="Effective script policy permits: " + ", ".join(risky_tokens),
                        remediation="Remove unsafe CSP tokens where possible and use nonces, hashes, and specific source allowlists.",
                        scope=FindingScope.HOST,
                        references=[Reference("MDN CSP", "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP")],
                    )
                )
            framed = any("frame-ancestors" in parse_csp(policy) for header in page.headers.get("content-security-policy", []) for policy in header.split(","))
            x_frame_options = (first_header(page.headers, "x-frame-options") or "").lower()
            if not framed and x_frame_options not in {"deny", "sameorigin"}:
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
        hsts = first_header(page.headers, "strict-transport-security")
        if hsts is not None and urllib.parse.urlsplit(page.final_url).scheme == "https":
            max_age = re.search(r"(?:^|;)\s*max-age\s*=\s*\"?(\d+)\"?\s*(?:;|$)", hsts, re.I)
            if not max_age or int(max_age.group(1)) == 0:
                findings.append(make_finding(
                    check=self.metadata.name, url=page.final_url, title="HSTS policy is disabled or invalid",
                    severity=Severity.MEDIUM, classification=Classification.WEAKNESS, confidence=Confidence.HIGH,
                    evidence="Strict-Transport-Security has no usable positive max-age.",
                    remediation="Set a valid positive max-age after verifying HTTPS support.", scope=FindingScope.HOST,
                ))
        nosniff = first_header(page.headers, "x-content-type-options")
        if nosniff is not None and nosniff.strip().lower() != "nosniff":
            findings.append(make_finding(
                check=self.metadata.name, url=page.final_url, title="X-Content-Type-Options has an invalid value",
                severity=Severity.LOW, classification=Classification.WEAKNESS, confidence=Confidence.HIGH,
                evidence="The header value is not nosniff.", remediation="Set X-Content-Type-Options: nosniff.", scope=FindingScope.HOST,
            ))
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
            parts = cookie.split(";")
            name = parts[0].partition("=")[0].strip()
            attributes = {part.partition("=")[0].strip().lower(): part.partition("=")[2].strip() for part in parts[1:]}
            if attributes.get("max-age") == "0":
                continue
            missing = [flag for flag in ("secure", "httponly", "samesite") if flag not in attributes]
            if missing:
                findings.append(
                    make_finding(
                        check=self.metadata.name,
                        url=page.final_url,
                        title="Cookie is missing recommended security attributes",
                        severity=Severity.MEDIUM if "secure" in missing else Severity.LOW,
                        classification=Classification.WEAKNESS,
                        confidence=Confidence.HIGH,
                        evidence=f"Cookie {name}: missing attributes: " + ", ".join(missing) + ". Cookie value omitted.",
                        remediation="Set Secure, HttpOnly, and SameSite attributes on sensitive cookies.",
                        scope=FindingScope.ENDPOINT,
                        dedup_key=f"cookie-attributes:{page.final_url}:{name}",
                    )
                )
            invalid = []
            if attributes.get("samesite", "").lower() == "none" and "secure" not in attributes:
                invalid.append("SameSite=None requires Secure")
            if "samesite" in attributes and attributes["samesite"].lower() not in {"strict", "lax", "none"}:
                invalid.append("SameSite has an unrecognized value")
            if name.startswith("__Secure-") and "secure" not in attributes:
                invalid.append("__Secure- prefix requires Secure")
            if name.startswith(("__Secure-", "__Host-")) and urllib.parse.urlsplit(page.final_url).scheme != "https":
                invalid.append("Cookie prefix requires an HTTPS origin")
            if "partitioned" in attributes and "secure" not in attributes:
                invalid.append("Partitioned cookies require Secure")
            if name.startswith("__Host-") and ("secure" not in attributes or "domain" in attributes or attributes.get("path") != "/"):
                invalid.append("__Host- prefix requires Secure, Path=/, and no Domain")
            if invalid:
                findings.append(make_finding(
                    check=self.metadata.name, url=page.final_url, title="Cookie has incompatible security attributes",
                    severity=Severity.MEDIUM, classification=Classification.WEAKNESS, confidence=Confidence.HIGH,
                    evidence=f"Cookie {name}: " + "; ".join(invalid) + ". Cookie value omitted.",
                    remediation="Correct the cookie attributes and confirm browser acceptance.",
                    scope=FindingScope.ENDPOINT, dedup_key=f"cookie-invalid:{page.final_url}:{name}",
                ))
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
