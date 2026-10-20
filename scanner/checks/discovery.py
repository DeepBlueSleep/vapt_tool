from __future__ import annotations
import re
import secrets

from scanner.checks.common import make_finding
from scanner.core.http import HttpClient
from scanner.core.models import Classification, Confidence, Finding, FindingScope, Reference, Severity
from scanner.utils.url import origin_for
from scanner.discovery.apis import api_response_evidence

SAFE_EXPOSURE_PATHS = (
    "/.env",
    "/.git/HEAD",
    "/backup.zip",
    "/backup.tar.gz",
    "/db.sql",
    "/phpinfo.php",
    "/server-status",
    "/debug",
    "/actuator",
    "/actuator/env",
    "/_profiler",
)

API_PATHS = ("/openapi.json", "/swagger.json", "/swagger/v1/swagger.json", "/graphql", "/api/graphql", "/.well-known/security.txt")


async def check_common_exposures(client: HttpClient, base_url: str) -> list[Finding]:
    findings: list[Finding] = []
    origin = origin_for(base_url)
    baseline = await client.get(origin + "/scanner-missing-" + secrets.token_hex(8))
    for path in SAFE_EXPOSURE_PATHS:
        response = await client.get(origin + path)
        if not response.body or (baseline.status == 200 and response.body == baseline.body):
            continue
        if path == "/.git/HEAD" and response.status == 200 and response.body.startswith(b"ref:"):
            findings.append(
                make_finding(
                    check="discovery.exposures",
                    url=response.final_url,
                    title="Git metadata is publicly reachable",
                    severity=Severity.CRITICAL,
                    classification=Classification.VULNERABILITY,
                    confidence=Confidence.HIGH,
                    evidence="/.git/HEAD returned repository metadata.",
                    remediation="Block public access to .git directories immediately.",
                    scope=FindingScope.PATH,
                )
            )
        elif response.status == 200 and _confirmed_exposure(path, response.body):
            findings.append(
                make_finding(
                    check="discovery.exposures",
                    url=response.final_url,
                    title="Sensitive file content is publicly reachable",
                    severity=Severity.HIGH,
                    classification=Classification.VULNERABILITY,
                    confidence=Confidence.MEDIUM,
                    evidence=f"{path} returned HTTP 200 and matched its expected content signature. Content omitted.",
                    remediation="Remove public access to sensitive files and verify deployment exclusions.",
                    scope=FindingScope.PATH,
                )
            )
    return findings


def _confirmed_exposure(path: str, body: bytes) -> bool:
    text = body.decode("utf-8", "ignore")
    if path == "/.env":
        return bool(re.search(r"(?m)^\s*(?:export\s+)?[A-Z_][A-Z0-9_]*(?:PASSWORD|SECRET|TOKEN|KEY|DATABASE_URL)[A-Z0-9_]*\s*=\s*\S+", text)
                    or re.search(r"(?m)^\s*(?:DATABASE_URL|SECRET_KEY|API_KEY)\s*=\s*\S+", text))
    if path.endswith(".zip"):
        return body.startswith(b"PK\x03\x04")
    if path.endswith(".tar.gz"):
        return body.startswith(b"\x1f\x8b")
    if path.endswith(".sql"):
        return bool(re.search(r"(?:CREATE TABLE|INSERT INTO|PostgreSQL database dump|MySQL dump)", text, re.I))
    if path == "/phpinfo.php":
        return "phpinfo()" in text and "PHP Version" in text
    if path == "/server-status":
        return "Apache Server Status" in text
    if path == "/actuator/env":
        return '"propertySources"' in text
    return False


async def discover_api_surface(client: HttpClient, base_url: str) -> list[Finding]:
    findings: list[Finding] = []
    origin = origin_for(base_url)
    for path in API_PATHS:
        response = await client.get(origin + path)
        if api_response_evidence(response, path):
            findings.append(
                make_finding(
                    check="discovery.api",
                    url=response.final_url,
                    title="API or security metadata endpoint discovered",
                    severity=Severity.INFO,
                    classification=Classification.RECOMMENDATION,
                    confidence=Confidence.MEDIUM,
                    evidence=f"{path} returned HTTP {response.status}.",
                    remediation=(
                        "Ensure discovered API and metadata endpoints expose only intended information "
                        "and require authentication where appropriate."
                    ),
                    scope=FindingScope.ENDPOINT,
                    references=[Reference("security.txt", "https://securitytxt.org/")],
                )
            )
    return findings
