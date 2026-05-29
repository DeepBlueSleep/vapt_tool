from __future__ import annotations

from scanner.checks.common import make_finding
from scanner.core.http import HttpClient
from scanner.core.models import Classification, Confidence, Finding, FindingScope, Reference, Severity
from scanner.utils.url import origin_for

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
    for path in SAFE_EXPOSURE_PATHS:
        response = await client.get(origin + path)
        content_type = (response.headers.get("content-type") or [""])[0]
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
        elif response.status == 200 and "text/html" not in content_type.lower():
            findings.append(
                make_finding(
                    check="discovery.exposures",
                    url=response.final_url,
                    title="Potentially sensitive file is publicly reachable",
                    severity=Severity.HIGH,
                    classification=Classification.VULNERABILITY,
                    confidence=Confidence.MEDIUM,
                    evidence=f"{path} returned HTTP 200 with Content-Type {content_type or 'unknown'}.",
                    remediation="Remove public access to sensitive files and verify deployment exclusions.",
                    scope=FindingScope.PATH,
                )
            )
    return findings


async def discover_api_surface(client: HttpClient, base_url: str) -> list[Finding]:
    findings: list[Finding] = []
    origin = origin_for(base_url)
    for path in API_PATHS:
        response = await client.get(origin + path)
        if response.status in {200, 401, 403}:
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
