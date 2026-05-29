from __future__ import annotations

import datetime as dt
import logging
import urllib.parse

from scanner.active.runtime_api_analysis import analyze_runtime_api
from scanner.auth.detection import detect_auth_signals
from scanner.browser.feedback import BrowserFeedbackState, feedback_candidates
from scanner.browser.network_capture import RuntimeApiKind, RuntimeApiRequest
from scanner.browser.playwright_analyzer import BrowserObservation, PlaywrightAnalyzer
from scanner.checks.active import SafeActiveCheck
from scanner.checks.discovery import check_common_exposures, discover_api_surface
from scanner.checks.fingerprints import TechnologyFingerprintCheck
from scanner.checks.passive import CookieCheck, HeaderCheck, HtmlPassiveCheck
from scanner.core.config import ScanConfig, ScopeConfig
from scanner.core.http import HttpClient
from scanner.core.models import Form, Page, TargetReport
from scanner.core.scope import Scope
from scanner.crawlers.async_crawler import AsyncCrawler
from scanner.crawlers.parser import extract_parameters, parse_html
from scanner.discovery.apis import discover_api_surfaces
from scanner.discovery.expansion import ExpansionSettings, expand_attack_surface
from scanner.discovery.fingerprints import correlate_fingerprints
from scanner.discovery.parameters import endpoint_signatures_from_page, harvest_page_parameters
from scanner.graph.surface import AttackSurfaceGraph, NodeKind
from scanner.js.analyzer import analyze_javascript
from scanner.js.frameworks import analyze_frameworks
from scanner.plugins.events import EventDispatcher, EventType
from scanner.plugins.registry import PluginRegistry
from scanner.risk.correlation import finalize_report_findings
from scanner.utils.url import normalize_url

LOGGER = logging.getLogger(__name__)


class Scanner:
    def __init__(self, config: ScanConfig) -> None:
        self.config = config
        self.registry = PluginRegistry()
        self.events = EventDispatcher()
        self.registry.register(HeaderCheck())
        self.registry.register(CookieCheck())
        self.registry.register(HtmlPassiveCheck())
        self.registry.register(TechnologyFingerprintCheck())
        self.feedback_state = BrowserFeedbackState()

    async def scan(self, raw_urls: list[str]) -> list[TargetReport]:
        reports: list[TargetReport] = []
        for raw_url in raw_urls:
            reports.append(await self.scan_target(raw_url))
        return reports

    async def scan_target(self, raw_url: str) -> TargetReport:
        report = TargetReport(input_url=raw_url, scanned_at_utc=dt.datetime.now(dt.UTC).isoformat())
        try:
            start_url = normalize_url(raw_url)
        except ValueError as exc:
            report.errors.append(str(exc))
            return report

        host = urllib.parse.urlparse(start_url).hostname or ""
        scope_config = self.config.scope
        if not scope_config.allowed_hosts:
            scope_config = ScopeConfig(
                allowed_hosts=frozenset({host}),
                deny_hosts=scope_config.deny_hosts,
                allowed_schemes=scope_config.allowed_schemes,
                allow_subdomains=scope_config.allow_subdomains,
                respect_robots_txt=scope_config.respect_robots_txt,
            )
            config = ScanConfig(**{**self.config.__dict__, "scope": scope_config})
        else:
            config = self.config

        scope = Scope(config.scope)
        async with HttpClient(config, scope) as client:
            if config.enable_active_checks:
                self.registry.register(SafeActiveCheck(client, request_budget=config.request_budget))
            crawler = AsyncCrawler(config, client, scope)
            pages = await crawler.crawl(start_url)
            graph = AttackSurfaceGraph()
            report.pages_crawled = len(pages)
            if pages:
                report.final_url = pages[0].final_url
                report.status_code = pages[0].status
            else:
                report.final_url = start_url
            for page in pages:
                await self._process_page(client, page, report, config, graph)
            if config.include_exposure_checks:
                report.findings.extend(await check_common_exposures(client, start_url))
            report.findings.extend(await discover_api_surface(client, start_url))
            await self._discover_apis(client, start_url, report)
            if config.enable_browser_checks:
                await self._run_browser_feedback(client, scope, start_url, report, config, graph)
            await self._expand_attack_surface(client, start_url, report, config, graph)
            report.metrics["http_requests"] = client.request_count
            report.metrics["http_request_time_ms"] = round(client.total_request_time_ms, 2)
            for key, value in graph.summary().items():
                report.metrics[f"graph_{key}"] = value
        report.metrics.update({f"events_{key}": value for key, value in self.events.counts.items()})
        finalize_report_findings(report)
        LOGGER.info("scan_complete", extra={"target": raw_url, "findings": len(report.findings), "pages": report.pages_crawled})
        return report

    async def _process_page(
        self,
        client: HttpClient,
        page: Page,
        report: TargetReport,
        config: ScanConfig,
        graph: AttackSurfaceGraph,
    ) -> None:
        await self.events.publish(EventType.RESPONSE_RECEIVED, url=page.final_url, status=page.status)
        page_node = graph.add_node(NodeKind.PAGE, page.final_url)
        report.inventory.setdefault("pages", []).append(page.final_url)
        report.inventory.setdefault("assets", [])
        report.inventory.setdefault("forms", [])
        report.inventory.setdefault("parameters", [])
        report.inventory.setdefault("endpoints", [])
        report.inventory["assets"].extend(asset for asset in (*page.assets, *page.scripts) if asset not in report.inventory["assets"])
        for script in page.scripts:
            script_node = graph.add_node(NodeKind.SCRIPT, script)
            graph.add_edge(page_node, script_node, "loads_script")
        report.inventory["forms"].extend(form.action for form in page.forms if form.action not in report.inventory["forms"])
        for signal in detect_auth_signals(page):
            item = f"{signal.kind} {signal.confidence:.2f} {signal.url}"
            if item not in report.inventory.setdefault("auth_signals", []):
                report.inventory["auth_signals"].append(item)
            auth_node = graph.add_node(NodeKind.AUTH, signal.url, signal_kind=signal.kind)
            graph.add_edge(page_node, auth_node, "auth_signal")
        for parameter in harvest_page_parameters(page):
            item = f"{parameter.method} {parameter.name} ({parameter.type.value}) from {parameter.source_url}"
            if item not in report.inventory["parameters"]:
                report.inventory["parameters"].append(item)
            param_node = graph.add_node(NodeKind.PARAMETER, parameter.name, source=parameter.source_url)
            graph.add_edge(page_node, param_node, "has_parameter")
            await self.events.publish(EventType.PARAMETER_FOUND, parameter=parameter.name, source=parameter.source_url)
        for signature in endpoint_signatures_from_page(page):
            item = f"{signature.method} {signature.url}"
            if item not in report.inventory["endpoints"]:
                report.inventory["endpoints"].append(item)
            endpoint_node = graph.add_node(NodeKind.API, signature.url, method=signature.method)
            graph.add_edge(page_node, endpoint_node, "declares_endpoint")
        for form in page.forms:
            form_node = graph.add_node(NodeKind.FORM, form.action, method=form.method)
            graph.add_edge(page_node, form_node, "contains_form")
            await self.events.publish(EventType.FORM_FOUND, action=form.action, method=form.method)
        await self._analyze_javascript(client, page.final_url, page.scripts, report, graph, page_node)
        for plugin in self.registry.plugins(include_active=config.enable_active_checks):
            findings = await plugin.analyze(page, report)
            report.findings.extend(findings)
            for finding in findings:
                await self.events.publish(EventType.FINDING_CREATED, finding=finding.title, url=finding.url)

    async def _analyze_javascript(
        self,
        client: HttpClient,
        base_url: str,
        scripts: tuple[str, ...],
        report: TargetReport,
        graph: AttackSurfaceGraph,
        page_node: str,
    ) -> None:
        report.inventory.setdefault("js_endpoints", [])
        report.inventory.setdefault("websockets", [])
        for script in scripts[:20]:
            await self.events.publish(EventType.JS_DISCOVERED, url=script)
            response = await client.get(script)
            if response.status != 200 or not response.body:
                continue
            content = response.body.decode("utf-8", "ignore")
            discovery = analyze_javascript(script, content, base_url)
            for name, version in discovery.frameworks.items():
                report.technologies.setdefault(f"js_framework:{name}", version)
            for insight in analyze_frameworks(script, content):
                report.technologies.setdefault(f"framework:{insight.name}", f"confidence={insight.confidence:.2f}")
                for hint in insight.environment_leak_hints:
                    item = f"{insight.name} {hint} in {script}"
                    if item not in report.inventory.setdefault("runtime_config_hints", []):
                        report.inventory["runtime_config_hints"].append(item)
            for endpoint in discovery.endpoints:
                if endpoint not in report.inventory["js_endpoints"]:
                    report.inventory["js_endpoints"].append(endpoint)
                    await self.events.publish(EventType.URL_DISCOVERED, url=endpoint, source=script)
                endpoint_node = graph.add_node(NodeKind.API, endpoint, source="javascript")
                graph.add_edge(page_node, endpoint_node, "js_discovers_api")
            for websocket in discovery.websocket_urls:
                if websocket not in report.inventory["websockets"]:
                    report.inventory["websockets"].append(websocket)
            for parameter in discovery.parameters:
                item = f"{parameter.method} {parameter.name} ({parameter.type.value}) from {parameter.source_url}"
                if item not in report.inventory.setdefault("parameters", []):
                    report.inventory["parameters"].append(item)

    async def _discover_apis(self, client: HttpClient, start_url: str, report: TargetReport) -> None:
        surfaces = await discover_api_surfaces(client, start_url)
        report.inventory.setdefault("api_surfaces", [])
        report.inventory.setdefault("endpoints", [])
        for surface in surfaces:
            item = f"{surface.kind} {surface.status} {surface.url}"
            if item not in report.inventory["api_surfaces"]:
                report.inventory["api_surfaces"].append(item)
            for endpoint in surface.endpoints:
                endpoint_item = f"{endpoint.method} {endpoint.url}"
                if endpoint_item not in report.inventory["endpoints"]:
                    report.inventory["endpoints"].append(endpoint_item)

    async def _expand_attack_surface(
        self,
        client: HttpClient,
        start_url: str,
        report: TargetReport,
        config: ScanConfig,
        graph: AttackSurfaceGraph,
    ) -> None:
        if not config.enable_attack_surface_expansion:
            return
        settings = ExpansionSettings(
            enabled=config.enable_attack_surface_expansion,
            framework_routes=config.enable_framework_expansion,
            predictable_locations=config.enable_predictable_locations,
            api_expansion=config.enable_api_expansion,
            runtime_expansion=config.enable_runtime_expansion,
            max_candidates=max(1, config.expansion_max_candidates),
            max_probe_requests=max(0, config.expansion_probe_budget),
            min_confidence=max(0.0, min(1.0, config.expansion_min_confidence)),
        )
        fingerprints = correlate_fingerprints({}, report.technologies, report.inventory)
        for fingerprint in fingerprints:
            report.technologies.setdefault(f"fingerprint:{fingerprint.name}", f"confidence={fingerprint.confidence:.2f}")
        candidates = await expand_attack_surface(
            client,
            start_url,
            technologies=report.technologies,
            inventory=report.inventory,
            settings=settings,
        )
        report.inventory.setdefault("expanded_attack_surface", [])
        report.inventory.setdefault("inferred_apis", [])
        report.inventory.setdefault("framework_routes", [])
        report.inventory.setdefault("predictable_locations", [])
        report.inventory.setdefault("verified_expanded_routes", [])
        for candidate in candidates:
            line = candidate.inventory_line()
            if line not in report.inventory["expanded_attack_surface"]:
                report.inventory["expanded_attack_surface"].append(line)
            if candidate.source == "framework" and line not in report.inventory["framework_routes"]:
                report.inventory["framework_routes"].append(line)
            if candidate.source == "predictable" and line not in report.inventory["predictable_locations"]:
                report.inventory["predictable_locations"].append(line)
            if candidate.kind in {"api", "graphql"} and line not in report.inventory["inferred_apis"]:
                report.inventory["inferred_apis"].append(line)
            if candidate.verified and line not in report.inventory["verified_expanded_routes"]:
                report.inventory["verified_expanded_routes"].append(line)
            node_kind = (
                NodeKind.API
                if candidate.kind in {"api", "graphql"}
                else NodeKind.AUTH
                if candidate.kind == "auth"
                else NodeKind.ROUTE
            )
            node = graph.add_node(
                node_kind,
                candidate.url,
                source=candidate.source,
                confidence=candidate.confidence_label.value,
                status=str(candidate.status or ""),
            )
            for parent in candidate.lineage:
                parent_node = graph.add_node(NodeKind.API if "/api" in parent or "graphql" in parent else NodeKind.ROUTE, parent)
                graph.add_edge(parent_node, node, "inferred_from")
        report.metrics["expanded_attack_surface"] = len(candidates)
        report.metrics["expanded_attack_surface_verified"] = sum(1 for candidate in candidates if candidate.verified)

    async def _run_browser_feedback(
        self,
        client: HttpClient,
        scope: Scope,
        start_url: str,
        report: TargetReport,
        config: ScanConfig,
        graph: AttackSurfaceGraph,
    ) -> None:
        urls_to_analyze = [start_url]
        analyzed: set[str] = set()
        for round_index in range(max(1, config.browser_max_rounds)):
            next_urls: list[str] = []
            for browser_url in urls_to_analyze:
                if browser_url in analyzed:
                    continue
                analyzed.add(browser_url)
                observation = await self._run_browser(browser_url, report, config)
                if observation is None:
                    continue
                self._record_browser_observation(observation, report, graph, browser_url)
                await self._analyze_runtime_apis(client, observation.runtime_apis, report, config, graph, browser_url)
                candidates = feedback_candidates(
                    tuple(observation.spa_routes),
                    tuple(observation.runtime_apis),
                    scope,
                    self.feedback_state,
                    depth=round_index + 1,
                    route_budget=config.browser_route_budget,
                    api_budget=config.browser_api_budget,
                )
                report.metrics["browser_feedback_candidates"] = report.metrics.get("browser_feedback_candidates", 0) + len(candidates)
                for candidate in candidates:
                    if config.trace_feedback_loop:
                        LOGGER.info(
                            "browser_feedback_candidate",
                            extra={"url": candidate.url, "score": candidate.score, "kind": candidate.kind.value},
                        )
                    page = await self._fetch_feedback_page(client, candidate.url)
                    if page:
                        report.pages_crawled += 1
                        await self._process_page(client, page, report, config, graph)
                    if candidate.kind.value in {"page", "auth"}:
                        next_urls.append(candidate.url)
            urls_to_analyze = next_urls[: config.browser_route_budget]

    async def _run_browser(self, start_url: str, report: TargetReport, config: ScanConfig) -> BrowserObservation | None:
        try:
            analyzer = PlaywrightAnalyzer(
                timeout_ms=config.browser_timeout_ms,
                screenshot_dir=config.out_dir / "screenshots",
                capture_screenshots=config.capture_screenshots,
            )
            observation = await analyzer.analyze(start_url)
        except RuntimeError as exc:
            report.errors.append(str(exc))
            return None
        return observation

    def _record_browser_observation(
        self,
        observation: BrowserObservation,
        report: TargetReport,
        graph: AttackSurfaceGraph,
        source_url: str,
    ) -> None:
        report.inventory.setdefault("browser_routes", [])
        report.inventory.setdefault("browser_network", [])
        report.inventory.setdefault("runtime_apis", [])
        report.inventory.setdefault("runtime_parameters", [])
        report.inventory.setdefault("dynamic_forms", [])
        report.inventory.setdefault("screenshots", [])
        report.inventory["browser_routes"].extend(
            route for route in observation.discovered_routes if route not in report.inventory["browser_routes"]
        )
        report.inventory["browser_network"].extend(
            request for request in observation.network_requests if request not in report.inventory["browser_network"]
        )
        source_node = graph.add_node(NodeKind.ROUTE, source_url)
        for route in observation.spa_routes:
            if self.config.trace_spa:
                LOGGER.info("spa_route", extra={"url": route.url, "source": route.source.value})
            route_node = graph.add_node(NodeKind.ROUTE, route.url, source=route.source.value)
            graph.add_edge(source_node, route_node, "runtime_transition")
        for api in observation.runtime_apis:
            if api.kind in {RuntimeApiKind.ANALYTICS, RuntimeApiKind.ASSET}:
                continue
            item = f"{api.method} {api.kind.value} {api.url}"
            if item not in report.inventory["runtime_apis"]:
                report.inventory["runtime_apis"].append(item)
            api_node = graph.add_node(NodeKind.API, api.url, method=api.method, api_kind=api.kind.value)
            graph.add_edge(source_node, api_node, "runtime_api_call")
            for field in api.request_fields:
                param_item = f"{field} from {api.url}"
                if param_item not in report.inventory["runtime_parameters"]:
                    report.inventory["runtime_parameters"].append(param_item)
        for mutation in observation.dom_mutations:
            if self.config.trace_dom:
                LOGGER.info("dom_mutation", extra={"url": mutation.source_url, "forms": len(mutation.forms), "links": len(mutation.links)})
            for form in mutation.forms:
                item = f"{form.method.upper()} {form.action} ({','.join(form.inputs)})"
                if item not in report.inventory["dynamic_forms"]:
                    report.inventory["dynamic_forms"].append(item)
        if observation.screenshot_path:
            report.inventory["screenshots"].append(observation.screenshot_path)
        if observation.console_errors:
            report.metrics["browser_console_errors"] = len(observation.console_errors)

    async def _analyze_runtime_apis(
        self,
        client: HttpClient,
        apis: list[RuntimeApiRequest],
        report: TargetReport,
        config: ScanConfig,
        graph: AttackSurfaceGraph,
        source_url: str,
    ) -> None:
        if not config.enable_active_checks:
            return
        budget = config.browser_api_budget
        for api in apis:
            if budget <= 0:
                break
            if api.kind in {RuntimeApiKind.ANALYTICS, RuntimeApiKind.ASSET, RuntimeApiKind.WEBSOCKET}:
                continue
            findings = await analyze_runtime_api(client, api, request_budget=budget)
            budget -= 1
            report.findings.extend(findings)
            for finding in findings:
                api_node = graph.add_node(NodeKind.API, api.url)
                finding_node = graph.add_node(NodeKind.PARAMETER, finding.title)
                graph.add_edge(api_node, finding_node, "runtime_finding")
                await self.events.publish(EventType.FINDING_CREATED, finding=finding.title, url=finding.url)
        if config.trace_runtime_api:
            LOGGER.info("runtime_api_analysis_complete", extra={"source": source_url, "remaining_budget": budget})

    async def _fetch_feedback_page(self, client: HttpClient, url: str) -> Page | None:
        response = await client.get(url)
        if response.status is None:
            return None
        content_type = (response.headers.get("content-type") or [""])[0]
        links: tuple[str, ...] = ()
        assets: tuple[str, ...] = ()
        scripts: tuple[str, ...] = ()
        forms: tuple[Form, ...] = ()
        if response.body and "html" in content_type.lower():
            links, assets, scripts, forms = parse_html(response.body, response.final_url)
        parameters = extract_parameters(list(links), forms)
        return Page(
            url=url,
            final_url=response.final_url,
            status=response.status,
            headers=response.headers,
            body=response.body,
            content_type=content_type,
            links=links,
            assets=assets,
            scripts=scripts,
            forms=forms,
            parameters=parameters,
        )
