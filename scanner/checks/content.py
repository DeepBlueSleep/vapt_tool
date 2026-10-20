from __future__ import annotations

import re
import urllib.parse

from bs4 import BeautifulSoup

from scanner.checks.common import make_finding
from scanner.core.models import Classification, Confidence, Finding, FindingScope, Page, Severity
from scanner.plugins.base import PluginMetadata


class ContentCheck:
    metadata = PluginMetadata(name="passive.content", version="1.0", category="passive",
                              description="Public content leaks, mixed content, forms, and asset integrity.")

    async def analyze(self, page: Page, _report: object) -> list[Finding]:
        if page.status is None:
            return []
        text = page.body.decode("utf-8", "ignore")
        findings: list[Finding] = []

        def add(title: str, evidence: str, remediation: str, severity: Severity = Severity.MEDIUM) -> None:
            findings.append(make_finding(
                check=self.metadata.name, url=page.final_url, title=title, severity=severity,
                classification=Classification.WEAKNESS, confidence=Confidence.MEDIUM,
                evidence=evidence, remediation=remediation, scope=FindingScope.ENDPOINT,
            ))

        signatures = {
            "Private key material exposed": r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----",
            "AWS access key identifier exposed": r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b",
            "GitHub token pattern exposed": r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b",
        }
        for title, pattern in signatures.items():
            if re.search(pattern, text):
                add(title, "Recognizable credential material found; value omitted from report.",
                    "Remove the exposed material and rotate any confirmed credentials.", Severity.HIGH)
        errors = {
            "Python traceback": "Traceback (most recent call last):",
            "Java exception": "java.lang.",
            "PHP fatal error": "Fatal error:",
            "SQL diagnostic": "You have an error in your SQL syntax",
            ".NET stack trace": "System.Data.SqlClient.SqlException",
        }
        matched = [label for label, signature in errors.items() if signature in text]
        if matched:
            add("Public response exposes diagnostic error details", "Matched signatures: " + ", ".join(matched),
                "Return generic errors and keep stack traces in private server logs.")
        if "html" not in page.content_type.lower():
            return findings
        soup = BeautifulSoup(text, "html.parser")
        if re.search(r"<title>\s*Index of /", text, re.I) and soup.find("a", href="../"):
            add("Directory listing is publicly accessible", "Directory index title and parent-directory link detected.",
                "Disable directory indexing and review the exposed files.")
        origin = urllib.parse.urlsplit(page.final_url)
        mixed: list[str] = []
        external_scripts = 0
        for tag in soup.find_all(["script", "link", "iframe", "img", "audio", "video"]):
            source = tag.get("src") or tag.get("href")
            if not isinstance(source, str):
                continue
            parsed = urllib.parse.urlsplit(urllib.parse.urljoin(page.final_url, source))
            if origin.scheme == "https" and parsed.scheme == "http":
                mixed.append(f"{tag.name}: {parsed.hostname}")
            if tag.name == "script" and parsed.hostname != origin.hostname and parsed.scheme in {"http", "https"}:
                if not tag.get("integrity"):
                    external_scripts += 1
        if mixed:
            add("HTTPS page references insecure resources", "; ".join(mixed[:10]),
                "Serve all resources over HTTPS.")
        if external_scripts:
            add("Third-party scripts lack subresource integrity", f"{external_scripts} external scripts lack integrity metadata.",
                "Use pinned, trusted scripts and integrity hashes where supported.", Severity.LOW)
        for form in page.forms:
            action = urllib.parse.urlsplit(urllib.parse.urljoin(page.final_url, form.action))
            if form.has_password and action.scheme != "https":
                add("Password form submits over unencrypted HTTP", "Password form action uses HTTP.",
                    "Serve the login page and form action exclusively over HTTPS.", Severity.HIGH)
            if form.method.upper() == "POST" and not any(
                any(token in name.lower() for token in ("csrf", "xsrf", "token", "nonce"))
                for name in (*form.inputs, *form.hidden_inputs)
            ):
                add("POST form has no visible anti-CSRF field", "No token-like field found; cookie and server-side defenses require manual review.",
                    "Verify CSRF protection, including SameSite cookies and server-side origin validation.", Severity.LOW)
        return findings
