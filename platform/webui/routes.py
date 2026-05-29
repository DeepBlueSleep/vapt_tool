from __future__ import annotations

import shutil
import time
from pathlib import Path
from platform.database.models import ReportArtifact, Scan
from platform.database.repository import AssessmentRepository
from platform.evidence.service import EvidenceBundleService
from platform.exports.pdf.service import PdfExportService
from platform.reporting.service import ReportService
from typing import Any

from fastapi import APIRouter, FastAPI, Form, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from scanner.core.config import ScanConfig
from scanner.utils.url import normalize_url

WEBUI_DIR = Path(__file__).parent
PDF_RENDERER_VERSION = "2026-05-webui-styled-pdf-v4"
templates = Jinja2Templates(directory=str(WEBUI_DIR / "templates"))


def register_webui(app: FastAPI) -> None:
    app.mount("/ui-static", StaticFiles(directory=str(WEBUI_DIR / "static")), name="ui-static")
    app.include_router(router)


router = APIRouter(include_in_schema=False)


@router.get("/", response_class=HTMLResponse)
async def dashboard(request: Request) -> Response:
    async with request.app.state.session_factory() as session:
        repo = AssessmentRepository(session)
        scans = await repo.list_scans(limit=30)
        metrics = await repo.metrics_summary()
    inventory_totals = _inventory_totals(scans)
    return templates.TemplateResponse(
        request,
        "dashboard.html",
        {
            "request": request,
            "scans": scans,
            "metrics": metrics,
            "inventory_totals": inventory_totals,
            "active_scans": sum(1 for scan in scans if scan.status in {"queued", "running"}),
        },
    )


@router.post("/scan")
async def start_scan(
    request: Request,
    target_url: str = Form(...),
    enable_browser: str | None = Form(default=None),
    enable_active_checks: str | None = Form(default=None),
    capture_screenshots: str | None = Form(default=None),
    max_depth: int = Form(default=1),
    max_pages: int = Form(default=25),
    request_budget: int = Form(default=40),
    report_mode: str = Form(default="external"),
    enable_attack_surface_expansion: str | None = Form(default=None),
    enable_framework_expansion: str | None = Form(default=None),
    enable_predictable_locations: str | None = Form(default=None),
    enable_api_expansion: str | None = Form(default=None),
    enable_runtime_expansion: str | None = Form(default=None),
    expansion_max_candidates: int = Form(default=50),
    expansion_probe_budget: int = Form(default=25),
    expansion_min_confidence: float = Form(default=0.35),
) -> RedirectResponse:
    try:
        normalized_target = normalize_url(target_url)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    browser_enabled = enable_browser == "on"
    active_enabled = enable_active_checks == "on"
    screenshots_enabled = capture_screenshots == "on"
    expansion_enabled = enable_attack_surface_expansion == "on"
    framework_enabled = enable_framework_expansion == "on"
    predictable_enabled = enable_predictable_locations == "on"
    api_expansion_enabled = enable_api_expansion == "on"
    runtime_expansion_enabled = enable_runtime_expansion == "on"
    config_payload = {
        "url": normalized_target,
        "max_depth": max_depth,
        "max_pages": max_pages,
        "enable_browser": browser_enabled,
        "enable_active_checks": active_enabled,
        "capture_screenshots": screenshots_enabled,
        "enable_attack_surface_expansion": expansion_enabled,
        "enable_framework_expansion": framework_enabled,
        "enable_predictable_locations": predictable_enabled,
        "enable_api_expansion": api_expansion_enabled,
        "enable_runtime_expansion": runtime_expansion_enabled,
        "expansion_max_candidates": expansion_max_candidates,
        "expansion_probe_budget": expansion_probe_budget,
        "expansion_min_confidence": expansion_min_confidence,
    }
    config_payload["request_budget"] = max(request_budget, 1)
    config_payload["report_mode"] = report_mode
    async with request.app.state.session_factory() as session:
        repo = AssessmentRepository(session)
        scan = await repo.create_scan(normalized_target, config=config_payload)
        await session.commit()
    config = ScanConfig(
        out_dir=request.app.state.output_dir / f"scan-{scan.id}",
        max_depth=max_depth,
        max_pages=max_pages,
        request_budget=max(request_budget, 1),
        enable_browser_checks=browser_enabled,
        enable_active_checks=active_enabled,
        capture_screenshots=screenshots_enabled,
        enable_attack_surface_expansion=expansion_enabled,
        enable_framework_expansion=framework_enabled,
        enable_predictable_locations=predictable_enabled,
        enable_api_expansion=api_expansion_enabled,
        enable_runtime_expansion=runtime_expansion_enabled,
        expansion_max_candidates=max(expansion_max_candidates, 1),
        expansion_probe_budget=max(expansion_probe_budget, 0),
        expansion_min_confidence=max(0.0, min(expansion_min_confidence, 1.0)),
    )
    request.app.state.scan_queue.enqueue(scan.id, scan.target_url, config)
    return RedirectResponse(url=f"/scan/{scan.id}", status_code=303)


@router.get("/scan/{scan_id}", response_class=HTMLResponse)
async def scan_detail(request: Request, scan_id: int) -> Response:
    scan = await _get_scan_or_404(request, scan_id)
    return templates.TemplateResponse(
        request,
        "scan_detail.html",
        {"request": request, "scan": scan, "progress": _progress(request, scan)},
    )


@router.post("/scan/{scan_id}/delete")
async def delete_scan(request: Request, scan_id: int) -> RedirectResponse:
    async with request.app.state.session_factory() as session:
        repo = AssessmentRepository(session)
        scan = await repo.get_scan(scan_id)
        if scan is None:
            raise HTTPException(status_code=404, detail="scan not found")
        request.app.state.scan_queue.cancel(scan_id)
        await repo.delete_scan(scan_id)
        await session.commit()
    _remove_scan_artifacts(request.app.state.output_dir, scan_id)
    return RedirectResponse(url="/", status_code=303)


@router.post("/scans/delete")
async def delete_all_scans(request: Request) -> RedirectResponse:
    async with request.app.state.session_factory() as session:
        repo = AssessmentRepository(session)
        scans = await repo.list_scans(limit=10_000)
        scan_ids = [scan.id for scan in scans]
        for scan_id in scan_ids:
            request.app.state.scan_queue.cancel(scan_id)
        await repo.delete_scans(scan_ids)
        await session.commit()
    for scan_id in scan_ids:
        _remove_scan_artifacts(request.app.state.output_dir, scan_id)
    return RedirectResponse(url="/", status_code=303)


@router.get("/scan/{scan_id}/status", response_class=HTMLResponse)
async def scan_status(request: Request, scan_id: int) -> Response:
    scan = await _get_scan_or_404(request, scan_id)
    template = "partials/scan_status.html"
    response = templates.TemplateResponse(
        request,
        template,
        {"request": request, "scan": scan, "progress": _progress(request, scan)},
    )
    if scan.status not in {"queued", "running"}:
        response.headers["HX-Trigger"] = "scan-complete"
    return response


@router.get("/reports/{scan_id}", response_class=HTMLResponse)
async def scan_reports(request: Request, scan_id: int, severity: str = "all", q: str = "") -> Response:
    scan = await _get_scan_or_404(request, scan_id)
    findings = _filter_findings(scan, severity, q)
    return templates.TemplateResponse(
        request,
        "reports.html",
        {
            "request": request,
            "scan": scan,
            "findings": findings,
            "severity": severity,
            "q": q,
            "inventory_groups": _inventory_groups(scan),
            "pdfs": _pdf_artifacts(scan),
        },
    )


@router.get("/reports/{scan_id}/external", response_class=HTMLResponse)
async def external_report(request: Request, scan_id: int) -> Response:
    scan = await _get_scan_or_404(request, scan_id)
    return HTMLResponse(ReportService().build_external(scan).html)


@router.get("/reports/{scan_id}/internal", response_class=HTMLResponse)
async def internal_report(request: Request, scan_id: int) -> Response:
    scan = await _get_scan_or_404(request, scan_id)
    return HTMLResponse(ReportService().build_internal(scan).html)


@router.post("/reports/{scan_id}/{audience}.pdf")
async def generate_pdf(request: Request, scan_id: int, audience: str) -> Response:
    if audience not in {"external", "internal"}:
        raise HTTPException(status_code=404, detail="unsupported report audience")
    scan = await _get_scan_or_404(request, scan_id)
    artifact = await _ensure_pdf(request, scan, audience)
    return templates.TemplateResponse(
        request,
        "partials/pdf_status.html",
        {"request": request, "scan": scan, "artifact": artifact, "audience": audience},
    )


@router.get("/reports/{scan_id}/{audience}.pdf")
async def download_pdf(request: Request, scan_id: int, audience: str) -> FileResponse:
    if audience not in {"external", "internal"}:
        raise HTTPException(status_code=404, detail="unsupported report audience")
    scan = await _get_scan_or_404(request, scan_id)
    artifact = await _ensure_pdf(request, scan, audience)
    if not artifact.storage_path:
        raise HTTPException(status_code=503, detail="PDF generation did not produce a file")
    path = Path(artifact.storage_path)
    if not path.exists():
        raise HTTPException(status_code=404, detail="PDF artifact is missing on disk")
    return FileResponse(
        path,
        media_type="application/pdf",
        filename=f"scan-{scan.id}-{audience}.pdf",
        headers={
            "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
            "Pragma": "no-cache",
            "Expires": "0",
        },
    )


@router.get("/findings", response_class=HTMLResponse)
async def findings(request: Request, severity: str = "all", q: str = "") -> Response:
    async with request.app.state.session_factory() as session:
        repo = AssessmentRepository(session)
        scans = await repo.list_scans(limit=50)
    all_findings = []
    for scan in scans:
        for finding in scan.findings:
            if severity != "all" and finding.severity != severity:
                continue
            haystack = f"{finding.title} {finding.url} {finding.evidence_summary}".lower()
            if q and q.lower() not in haystack:
                continue
            all_findings.append((scan, finding))
    return templates.TemplateResponse(
        request,
        "findings.html",
        {"request": request, "items": all_findings, "severity": severity, "q": q},
    )


@router.get("/evidence/{scan_id}", response_class=HTMLResponse)
async def evidence_viewer(request: Request, scan_id: int) -> Response:
    scan = await _get_scan_or_404(request, scan_id)
    return templates.TemplateResponse(request, "evidence.html", {"request": request, "scan": scan})


@router.get("/evidence/{scan_id}/bundle.zip")
async def evidence_bundle(request: Request, scan_id: int) -> FileResponse:
    scan = await _get_scan_or_404(request, scan_id)
    path = request.app.state.output_dir / f"scan-{scan.id}" / "evidence-bundle.zip"
    EvidenceBundleService().create_bundle(scan, path)
    return FileResponse(path, media_type="application/zip", filename=f"scan-{scan.id}-evidence.zip")


@router.get("/evidence/file/{evidence_id}")
async def evidence_file(request: Request, evidence_id: int) -> FileResponse:
    async with request.app.state.session_factory() as session:
        from platform.database.models import Evidence

        evidence = await session.get(Evidence, evidence_id)
    if evidence is None or not evidence.storage_path:
        raise HTTPException(status_code=404, detail="evidence not found")
    path = Path(evidence.storage_path)
    if not path.exists():
        raise HTTPException(status_code=404, detail="evidence file is missing on disk")
    return FileResponse(path, media_type=evidence.content_type, filename=path.name)


async def _get_scan_or_404(request: Request, scan_id: int) -> Scan:
    async with request.app.state.session_factory() as session:
        repo = AssessmentRepository(session)
        scan = await repo.get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="scan not found")
    return scan


async def _ensure_pdf(request: Request, scan: Scan, audience: str) -> ReportArtifact:
    existing = next(
        (
            report
            for report in scan.reports
            if report.audience == audience and report.format == "pdf" and report.storage_path and Path(report.storage_path).exists()
            and report.metadata_json.get("renderer_version") == PDF_RENDERER_VERSION
            and not _pdf_contains_css_leak(Path(report.storage_path))
        ),
        None,
    )
    if existing is not None:
        return existing
    service = ReportService()
    bundle = service.build_external(scan) if audience == "external" else service.build_internal(scan)
    output = request.app.state.output_dir / f"scan-{scan.id}" / f"{audience}.pdf"
    output.unlink(missing_ok=True)
    started = time.perf_counter()
    try:
        path = await PdfExportService().render_pdf(bundle.html, output)
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    duration_ms = round((time.perf_counter() - started) * 1000, 1)
    metadata = {
        "duration_ms": duration_ms,
        "size_bytes": path.stat().st_size if path.exists() else 0,
        "renderer_version": PDF_RENDERER_VERSION,
        "renderer": "styled",
    }
    async with request.app.state.session_factory() as session:
        artifact = await _upsert_pdf_artifact(session, scan.id, audience, path, metadata)
        await session.commit()
        return artifact


def _progress(request: Request, scan: Scan) -> dict[str, Any]:
    live = request.app.state.progress_hub.snapshot(scan.id) if hasattr(request.app.state, "progress_hub") else None
    if scan.status == "completed":
        percent = 100
    elif scan.status == "failed":
        percent = 100
    elif scan.status == "running":
        percent = int(live.get("percent", 35)) if live else _estimated_running_percent(scan)
    else:
        percent = int(live.get("percent", 8)) if live else 8
    inventory = scan.inventory or {}
    live_events = live.get("events", {}) if live else {}
    live_recent = live.get("recent", []) if live else []
    return {
        "percent": percent,
        "pages": scan.pages_crawled,
        "apis": len(inventory.get("runtime_apis", [])) + len(inventory.get("endpoints", [])),
        "routes": len(inventory.get("browser_routes", [])) + len(inventory.get("pages", [])),
        "screenshots": len(inventory.get("screenshots", [])),
        "findings": len(scan.findings),
        "active_checks": sum(1 for finding in scan.findings if finding.classification == "vulnerability"),
        "expanded": len(inventory.get("expanded_attack_surface", [])),
        "verified_expanded": len(inventory.get("verified_expanded_routes", [])),
        "stage": live.get("stage") if live and scan.status in {"queued", "running"} else _stage(scan),
        "events": live_events,
        "recent": live_recent,
        "updated_at": live.get("updated_at") if live else None,
        "requests_seen": live_events.get("response_received", 0),
        "urls_seen": live_events.get("url_discovered", 0),
        "js_seen": live_events.get("js_discovered", 0),
        "params_seen": live_events.get("parameter_found", 0),
    }


def _stage(scan: Scan) -> str:
    if scan.status == "queued":
        return "Queued for assessment"
    if scan.status == "running":
        return "Crawling, runtime discovery, and checks in progress"
    if scan.status == "completed":
        return "Assessment complete"
    if scan.status == "failed":
        return "Assessment failed"
    return scan.status.title()


def _estimated_running_percent(scan: Scan) -> int:
    config = scan.config or {}
    max_pages = max(int(config.get("max_pages") or 25), 1)
    page_ratio = min(scan.pages_crawled / max_pages, 1.0)
    return max(22, min(88, round(22 + page_ratio * 60)))


def _inventory_totals(scans: list[Scan]) -> dict[str, int]:
    totals = {"apis": 0, "routes": 0, "screenshots": 0, "attack_surface": 0}
    for scan in scans:
        inventory = scan.inventory or {}
        apis = len(inventory.get("runtime_apis", [])) + len(inventory.get("endpoints", []))
        routes = len(inventory.get("browser_routes", [])) + len(inventory.get("pages", []))
        screenshots = len(inventory.get("screenshots", []))
        totals["apis"] += apis
        totals["routes"] += routes
        totals["screenshots"] += screenshots
        totals["attack_surface"] += apis + routes + len(inventory.get("parameters", [])) + len(inventory.get("auth_signals", []))
    return totals


def _inventory_groups(scan: Scan) -> list[tuple[str, list[str]]]:
    inventory = scan.inventory or {}
    keys = (
        "expanded_attack_surface",
        "inferred_apis",
        "framework_routes",
        "predictable_locations",
        "verified_expanded_routes",
        "pages",
        "browser_routes",
        "runtime_apis",
        "endpoints",
        "auth_signals",
        "parameters",
        "runtime_parameters",
        "dynamic_forms",
    )
    return [(key, inventory.get(key, [])) for key in keys if inventory.get(key)]


def _filter_findings(scan: Scan, severity: str, query: str) -> list[Any]:
    findings = []
    for finding in scan.findings:
        if severity != "all" and finding.severity != severity:
            continue
        haystack = f"{finding.title} {finding.url} {finding.evidence_summary} {finding.remediation}".lower()
        if query and query.lower() not in haystack:
            continue
        findings.append(finding)
    return findings


def _pdf_artifacts(scan: Scan) -> dict[str, Any]:
    return {
        audience: next(
            (
                report
                for report in scan.reports
                if report.audience == audience
                and report.format == "pdf"
                and report.storage_path
                and Path(report.storage_path).exists()
                and report.metadata_json.get("renderer_version") == PDF_RENDERER_VERSION
                and not _pdf_contains_css_leak(Path(report.storage_path))
            ),
            None,
        )
        for audience in ("external", "internal")
    }


def _pdf_contains_css_leak(path: Path) -> bool:
    try:
        sample = path.read_bytes()[:20_000]
    except OSError:
        return True
    markers = (b":root", b"color-scheme", b"@media", b"body{", b".panel{", b"</style>")
    return any(marker in sample for marker in markers)


def _remove_scan_artifacts(output_dir: Path, scan_id: int) -> None:
    path = output_dir / f"scan-{scan_id}"
    try:
        if path.is_dir():
            shutil.rmtree(path)
        elif path.exists():
            path.unlink()
    except OSError:
        return


async def _upsert_pdf_artifact(
    session: AsyncSession,
    scan_id: int,
    audience: str,
    path: Path,
    metadata: dict[str, Any],
) -> ReportArtifact:
    artifacts = list(
        (
            await session.scalars(
                select(ReportArtifact)
                .where(ReportArtifact.scan_id == scan_id)
                .where(ReportArtifact.audience == audience)
                .where(ReportArtifact.format == "pdf")
                .order_by(ReportArtifact.created_at.asc())
            )
        ).all()
    )
    if artifacts:
        artifact = artifacts[0]
        artifact.title = f"{audience.title()} PDF"
        artifact.storage_path = str(path)
        artifact.metadata_json = metadata
        for duplicate in artifacts[1:]:
            duplicate.storage_path = str(path)
            duplicate.metadata_json = {**metadata, "duplicate_of": artifact.id}
        await session.flush()
        return artifact
    artifact = ReportArtifact(
        scan_id=scan_id,
        audience=audience,
        format="pdf",
        title=f"{audience.title()} PDF",
        storage_path=str(path),
        metadata_json=metadata,
    )
    session.add(artifact)
    await session.flush()
    return artifact
