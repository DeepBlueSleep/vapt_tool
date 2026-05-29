from __future__ import annotations

from scanner.active.reflection import analyze_reflections
from scanner.checks.common import make_finding
from scanner.core.http import HttpClient
from scanner.core.models import Classification, Confidence, Finding, FindingScope, Page, Severity
from scanner.plugins.base import PluginMetadata


class SafeActiveCheck:
    metadata = PluginMetadata(
        name="active.safe_heuristics",
        version="1.0",
        description="Low-impact active checks for CORS, redirects, HTTP methods, and benign reflection.",
        category="active",
        active=True,
    )

    def __init__(self, client: HttpClient, request_budget: int = 40) -> None:
        self.client = client
        self.request_budget = request_budget

    async def analyze(self, page: Page, _report: object) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(await self._cors(page))
        findings.extend(await self._options(page))
        findings.extend(await self._reflection(page))
        findings.extend(await self._open_redirect(page))
        findings.extend(self._weak_cache_headers(page))
        return findings

    async def _cors(self, page: Page) -> list[Finding]:
        response = await self.client.request("GET", page.final_url, retries=0)
        allow_origin = (response.headers.get("access-control-allow-origin") or [""])[0]
        allow_credentials = (response.headers.get("access-control-allow-credentials") or [""])[0].lower()
        if allow_origin == "*" and allow_credentials == "true":
            return [
                make_finding(
                    check=self.metadata.name,
                    url=page.final_url,
                    title="Permissive CORS configuration detected",
                    severity=Severity.HIGH,
                    classification=Classification.WEAKNESS,
                    confidence=Confidence.HIGH,
                    evidence="Access-Control-Allow-Origin is * and credentials are allowed.",
                    remediation="Use a strict origin allowlist and avoid wildcard CORS with credentials.",
                )
            ]
        return []

    def _weak_cache_headers(self, page: Page) -> list[Finding]:
        if not any(form.has_password for form in page.forms) and "set-cookie" not in page.headers:
            return []
        cache_control = ",".join(page.headers.get("cache-control", [])).lower()
        pragma = ",".join(page.headers.get("pragma", [])).lower()
        if "no-store" in cache_control:
            return []
        return [
            make_finding(
                check=self.metadata.name,
                url=page.final_url,
                title="Sensitive response may be cacheable",
                severity=Severity.LOW,
                classification=Classification.WEAKNESS,
                confidence=Confidence.MEDIUM,
                evidence=f"Cache-Control={cache_control or 'missing'}; Pragma={pragma or 'missing'}.",
                remediation="Use Cache-Control: no-store for sensitive responses that set cookies or contain authentication forms.",
                scope=FindingScope.ENDPOINT,
            )
        ]

    async def _options(self, page: Page) -> list[Finding]:
        response = await self.client.request("OPTIONS", page.final_url, max_body=0, retries=0)
        methods = ",".join(response.headers.get("allow", []) + response.headers.get("access-control-allow-methods", [])).upper()
        dangerous = [method for method in ("PUT", "DELETE", "TRACE") if method in methods]
        if dangerous:
            return [
                make_finding(
                    check=self.metadata.name,
                    url=page.final_url,
                    title="Dangerous HTTP methods advertised",
                    severity=Severity.MEDIUM,
                    classification=Classification.WEAKNESS,
                    confidence=Confidence.MEDIUM,
                    evidence="Advertised methods: " + ", ".join(dangerous),
                    remediation="Disable unnecessary HTTP methods at the application or edge layer.",
                )
            ]
        return []

    async def _reflection(self, page: Page) -> list[Finding]:
        findings = []
        for observation in await analyze_reflections(self.client, page, budget=min(5, self.request_budget)):
            contexts = ", ".join(context.value for context in observation.contexts)
            findings.append(
                make_finding(
                    check=self.metadata.name,
                    url=observation.test_url,
                    title="User input is reflected in the response",
                    severity=Severity.LOW,
                    classification=Classification.WEAKNESS,
                    confidence=Confidence.MEDIUM,
                    evidence=f"Benign marker reflected for parameter {observation.parameter.name} in contexts: {contexts}.",
                    remediation="Contextually encode reflected input and validate parameters server-side.",
                    scope=FindingScope.PARAMETER,
                    metadata={
                        "parameter": observation.parameter.name,
                        "endpoint": page.final_url,
                        "contexts": [context.value for context in observation.contexts],
                    },
                )
            )
        return findings

    async def _open_redirect(self, page: Page) -> list[Finding]:
        import urllib.parse

        redirect_params = [param for param in page.parameters if param.lower() in {"next", "url", "redirect", "redirect_uri", "return"}]
        if not redirect_params:
            return []
        parsed = urllib.parse.urlparse(page.final_url)
        query = dict(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))
        query[redirect_params[0]] = "https://example.com/"
        test_url = urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(query)))
        response = await self.client.get(test_url)
        if response.final_url.startswith("https://example.com"):
            return [
                make_finding(
                    check=self.metadata.name,
                    url=test_url,
                    title="Potential open redirect behavior detected",
                    severity=Severity.MEDIUM,
                    classification=Classification.WEAKNESS,
                    confidence=Confidence.MEDIUM,
                    evidence="A redirect-like parameter navigated to example.com.",
                    remediation="Validate redirect targets against a strict relative-path or origin allowlist.",
                    scope=FindingScope.PARAMETER,
                    metadata={"parameter": redirect_params[0], "endpoint": page.final_url},
                )
            ]
        return []
