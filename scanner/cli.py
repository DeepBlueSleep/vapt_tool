from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

from scanner.core.config import ScanConfig, ScopeConfig
from scanner.core.models import TargetReport
from scanner.core.orchestrator import Scanner
from scanner.reporting.diff import compare_report_files, render_diff_markdown
from scanner.reporting.reports import has_blocking_vulnerability, summarize_by_classification, summarize_by_severity, write_reports
from scanner.utils.logging import configure_logging


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run a safe asynchronous website security assessment.")
    parser.add_argument("urls", nargs="+", help="Website URLs or hostnames to scan.")
    parser.add_argument("--out-dir", default="audit-reports", help="Directory for generated reports.")
    parser.add_argument("--timeout", type=float, default=10.0, help="Network timeout in seconds.")
    parser.add_argument("--max-depth", type=int, default=1, help="Maximum crawl depth.")
    parser.add_argument("--max-pages", type=int, default=25, help="Maximum pages per target.")
    parser.add_argument("--concurrency", type=int, default=4, help="Bounded concurrent requests per target.")
    parser.add_argument("--rate-limit", type=float, default=1.0, help="Requests per second per target.")
    parser.add_argument("--allow-subdomains", action="store_true", help="Permit crawling subdomains of the input host.")
    parser.add_argument("--deny-host", action="append", default=[], help="Host to exclude from scope. Can be repeated.")
    parser.add_argument("--ignore-robots", action="store_true", help="Do not consult robots.txt before crawling.")
    parser.add_argument("--skip-exposure-checks", action="store_true", help="Skip checks for commonly exposed files.")
    parser.add_argument("--enable-active-checks", action="store_true", help="Opt in to low-impact active heuristic checks.")
    parser.add_argument("--request-budget", type=int, default=40, help="Maximum low-impact active requests per target.")
    parser.add_argument("--browser", action="store_true", help="Enable optional Playwright browser-assisted analysis.")
    parser.add_argument("--browser-timeout", type=int, default=15_000, help="Browser page timeout in milliseconds.")
    parser.add_argument("--browser-route-budget", type=int, default=20, help="Maximum browser-discovered routes to feed back per round.")
    parser.add_argument("--browser-api-budget", type=int, default=20, help="Maximum browser-discovered APIs to analyze per target.")
    parser.add_argument("--browser-max-rounds", type=int, default=1, help="Maximum recursive browser feedback rounds.")
    parser.add_argument("--capture-screenshots", action="store_true", help="Capture browser screenshots when --browser is enabled.")
    parser.add_argument("--disable-expansion", action="store_true", help="Disable intelligent attack-surface expansion.")
    parser.add_argument("--disable-framework-expansion", action="store_true", help="Disable framework-aware route inference.")
    parser.add_argument("--disable-predictable-locations", action="store_true", help="Disable bounded predictable-location analysis.")
    parser.add_argument("--disable-api-expansion", action="store_true", help="Disable recursive API route inference.")
    parser.add_argument("--disable-runtime-expansion", action="store_true", help="Disable runtime-driven route/API inference.")
    parser.add_argument("--expansion-candidates", type=int, default=50, help="Maximum inferred attack-surface candidates per target.")
    parser.add_argument("--expansion-probe-budget", type=int, default=25, help="Maximum low-impact HEAD probes for inferred candidates.")
    parser.add_argument("--expansion-min-confidence", type=float, default=0.35, help="Minimum confidence for inferred candidates.")
    parser.add_argument("--metrics", action="store_true", help="Include scan metrics in reports.")
    parser.add_argument("--trace-requests", action="store_true", help="Emit structured logs for each HTTP request.")
    parser.add_argument("--trace-spa", action="store_true", help="Emit browser SPA route trace logs.")
    parser.add_argument("--trace-dom", action="store_true", help="Emit DOM mutation trace logs.")
    parser.add_argument("--trace-runtime-api", action="store_true", help="Emit runtime API trace logs.")
    parser.add_argument("--trace-feedback-loop", action="store_true", help="Emit browser-to-crawler feedback trace logs.")
    parser.add_argument(
        "--report-mode",
        choices=("executive", "technical", "developer", "compliance", "api-focused", "runtime-focused"),
        default="technical",
        help="Audience-specific report mode.",
    )
    parser.add_argument(
        "--export",
        action="append",
        default=[],
        choices=("sarif", "csv", "junit", "github-security"),
        help="Additional export format. Can be repeated.",
    )
    parser.add_argument("--baseline", help="Previous JSON report to compare against.")
    parser.add_argument("--persist", action="store_true", help="Persist scan results to the assessment platform database.")
    parser.add_argument("--database-url", default="sqlite+aiosqlite:///./platform.db", help="Assessment platform database URL.")
    parser.add_argument("--owner", help="Optional scan owner for platform persistence.")
    parser.add_argument("--verbose", action="store_true", help="Enable debug structured logs.")
    return parser.parse_args(argv)


async def async_main(argv: list[str]) -> int:
    args = parse_args(argv)
    configure_logging(args.verbose)
    config = ScanConfig(
        out_dir=Path(args.out_dir),
        timeout_seconds=max(args.timeout, 1.0),
        max_depth=max(args.max_depth, 0),
        max_pages=max(args.max_pages, 1),
        concurrency=max(args.concurrency, 1),
        rate_limit_per_second=max(args.rate_limit, 0.1),
        include_exposure_checks=not args.skip_exposure_checks,
        enable_active_checks=args.enable_active_checks,
        request_budget=max(args.request_budget, 1),
        enable_browser_checks=args.browser,
        browser_timeout_ms=max(args.browser_timeout, 1000),
        browser_route_budget=max(args.browser_route_budget, 1),
        browser_api_budget=max(args.browser_api_budget, 1),
        browser_max_rounds=max(args.browser_max_rounds, 1),
        capture_screenshots=args.capture_screenshots,
        enable_attack_surface_expansion=not args.disable_expansion,
        enable_framework_expansion=not args.disable_framework_expansion,
        enable_predictable_locations=not args.disable_predictable_locations,
        enable_api_expansion=not args.disable_api_expansion,
        enable_runtime_expansion=not args.disable_runtime_expansion,
        expansion_max_candidates=max(args.expansion_candidates, 1),
        expansion_probe_budget=max(args.expansion_probe_budget, 0),
        expansion_min_confidence=max(0.0, min(args.expansion_min_confidence, 1.0)),
        emit_metrics=args.metrics,
        trace_requests=args.trace_requests,
        trace_spa=args.trace_spa,
        trace_dom=args.trace_dom,
        trace_runtime_api=args.trace_runtime_api,
        trace_feedback_loop=args.trace_feedback_loop,
        scope=ScopeConfig(
            deny_hosts=frozenset(host.lower() for host in args.deny_host),
            allow_subdomains=args.allow_subdomains,
            respect_robots_txt=not args.ignore_robots,
        ),
    )
    reports = await Scanner(config).scan(args.urls)
    if args.persist:
        await _persist_reports(args.database_url, reports, args.owner, config)
    json_path, md_path, html_path = write_reports(reports, config.out_dir, report_mode=args.report_mode, export_formats=tuple(args.export))
    if args.baseline:
        diff = compare_report_files(Path(args.baseline), json_path)
        diff_path = config.out_dir / f"{json_path.stem}-diff.md"
        diff_path.write_text(render_diff_markdown(diff), encoding="utf-8")
    severity_summary = summarize_by_severity(reports)
    classification_summary = summarize_by_classification(reports)
    print(f"Wrote JSON report: {json_path}")
    print(f"Wrote Markdown report: {md_path}")
    print(f"Wrote HTML report: {html_path}")
    if args.baseline:
        print(f"Wrote Diff report: {diff_path}")
    severity_text = ", ".join(
        f"{severity}={severity_summary[severity]}" for severity in ("critical", "high", "medium", "low", "info")
    )
    print("Severity: " + severity_text)
    print(
        "Classification: "
        + ", ".join(
            f"{classification}={classification_summary[classification]}"
            for classification in ("vulnerability", "weakness", "recommendation")
        )
    )
    return 1 if has_blocking_vulnerability(reports) else 0


def main(argv: list[str] | None = None) -> int:
    return asyncio.run(async_main(sys.argv[1:] if argv is None else argv))


async def _persist_reports(database_url: str, reports: list[TargetReport], owner: str | None, config: ScanConfig) -> None:
    from platform.database.migrations import migrate
    from platform.database.repository import AssessmentRepository

    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    engine = create_async_engine(database_url, future=True)
    await migrate(engine)
    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    async with session_factory() as session:
        repo = AssessmentRepository(session)
        for report in reports:
            scan = await repo.create_scan(report.input_url, config={"source": "cli", "out_dir": str(config.out_dir)}, owner=owner)
            await repo.persist_target_report(scan.id, report)
        await session.commit()
    await engine.dispose()


if __name__ == "__main__":
    raise SystemExit(main())
