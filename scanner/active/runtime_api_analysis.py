from __future__ import annotations

import urllib.parse

from scanner.analysis.diffing import ResponseSnapshot, compare_responses
from scanner.browser.network_capture import RuntimeApiKind, RuntimeApiRequest, json_fields
from scanner.checks.common import make_finding
from scanner.core.http import HttpClient, HttpResponse
from scanner.core.models import Classification, Confidence, Finding, FindingScope, Severity


async def analyze_runtime_api(client: HttpClient, api: RuntimeApiRequest, request_budget: int = 10) -> list[Finding]:
    if request_budget <= 0 or api.method.upper() not in {"GET", "HEAD"} or api.kind in {RuntimeApiKind.ANALYTICS, RuntimeApiKind.ASSET, RuntimeApiKind.WEBSOCKET}:
        return []
    findings: list[Finding] = []
    response = await client.request("GET", api.url, active=True)
    fields = json_fields(response.body)
    if fields and any(field.lower() in {"debug", "trace", "stack", "exception", "sql"} for field in fields):
        findings.append(
            make_finding(
                check="active.runtime_api",
                url=api.url,
                title="Runtime API response exposes verbose diagnostic fields",
                severity=Severity.MEDIUM,
                classification=Classification.WEAKNESS,
                confidence=Confidence.MEDIUM,
                evidence="Diagnostic-like JSON fields: " + ", ".join(fields[:10]),
                remediation="Remove debug, trace, stack, and internal diagnostic fields from production API responses.",
                scope=FindingScope.ENDPOINT,
            )
        )
    if request_budget > 1:
        findings.extend(await _json_reflection(client, api, response))
    if api.kind == RuntimeApiKind.GRAPHQL and response.status in {200, 400}:
        findings.append(
            make_finding(
                check="active.runtime_api",
                url=api.url,
                title="GraphQL endpoint is reachable",
                severity=Severity.INFO,
                classification=Classification.RECOMMENDATION,
                confidence=Confidence.MEDIUM,
                evidence=f"GraphQL-like endpoint returned HTTP {response.status}.",
                remediation="Confirm GraphQL schema exposure, auth requirements, and production error handling are intentional.",
                scope=FindingScope.ENDPOINT,
            )
        )
    return findings


async def _json_reflection(client: HttpClient, api: RuntimeApiRequest, baseline_response: HttpResponse) -> list[Finding]:
    if not api.request_fields:
        return []
    marker = "scanner-json-marker"
    parsed = urllib.parse.urlparse(api.url)
    query = dict(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))
    query[api.request_fields[0]] = marker
    test_url = urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(query)))
    candidate = await client.request("GET", test_url, active=True)
    baseline = ResponseSnapshot(
        api.url,
        baseline_response.final_url,
        baseline_response.status,
        baseline_response.headers,
        baseline_response.body,
    )
    snapshot = ResponseSnapshot(test_url, candidate.final_url, candidate.status, candidate.headers, candidate.body)
    diff = compare_responses(baseline, snapshot, (marker,))
    if not diff.reflected_markers:
        return []
    return [
        make_finding(
            check="active.runtime_api",
            url=test_url,
            title="Runtime API reflects JSON or query input",
            severity=Severity.LOW,
            classification=Classification.WEAKNESS,
            confidence=Confidence.MEDIUM,
            evidence=f"Benign marker reflected in API response for parameter {api.request_fields[0]}.",
            remediation="Validate and encode reflected API input in the response context.",
            scope=FindingScope.PARAMETER,
            metadata={"parameter": api.request_fields[0], "endpoint": api.url},
        )
    ]
