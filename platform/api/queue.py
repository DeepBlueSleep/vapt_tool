from __future__ import annotations

import asyncio
import datetime as dt
from collections import defaultdict
from pathlib import Path
from platform.api.schemas import ScanCreate
from platform.database.models import ScanStatus
from platform.database.repository import AssessmentRepository
from platform.reporting.service import ReportService
from typing import Any

from fastapi import WebSocket
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from scanner.core.config import ScanConfig
from scanner.core.orchestrator import Scanner
from scanner.plugins.events import EventType, ScannerEvent


class ProgressHub:
    def __init__(self) -> None:
        self._sockets: dict[int, set[WebSocket]] = defaultdict(set)
        self._state: dict[int, dict[str, Any]] = {}

    async def connect(self, scan_id: int, websocket: WebSocket) -> None:
        await websocket.accept()
        self._sockets[scan_id].add(websocket)

    def disconnect(self, scan_id: int, websocket: WebSocket) -> None:
        self._sockets[scan_id].discard(websocket)

    async def publish(self, scan_id: int, event: str, payload: dict[str, Any] | None = None) -> None:
        message = {"scan_id": scan_id, "event": event, "payload": payload or {}}
        stale = []
        for websocket in self._sockets.get(scan_id, set()):
            try:
                await websocket.send_json(message)
            except RuntimeError:
                stale.append(websocket)
        for websocket in stale:
            self.disconnect(scan_id, websocket)

    def initialize(self, scan_id: int, config: ScanConfig) -> None:
        self._state[scan_id] = {
            "status": "queued",
            "stage": "Waiting for an available worker",
            "percent": 8,
            "started_at": None,
            "updated_at": dt.datetime.now(dt.UTC).isoformat(),
            "events": {},
            "recent": [],
            "expected_work": _expected_work(config),
        }

    def start(self, scan_id: int) -> None:
        state = self._state.setdefault(scan_id, {})
        state.update(
            {
                "status": "running",
                "stage": "Crawler started",
                "percent": max(int(state.get("percent", 0)), 18),
                "started_at": dt.datetime.now(dt.UTC).isoformat(),
                "updated_at": dt.datetime.now(dt.UTC).isoformat(),
            }
        )

    def record_scanner_event(self, scan_id: int, event: ScannerEvent) -> None:
        state = self._state.setdefault(scan_id, {"events": {}, "recent": [], "expected_work": 40})
        events = state.setdefault("events", {})
        events[event.type.value] = int(events.get(event.type.value, 0)) + 1
        recent = state.setdefault("recent", [])
        recent.append(_event_line(event))
        del recent[:-8]
        state["stage"] = _stage_from_event(event)
        state["percent"] = _event_percent(events, int(state.get("expected_work") or 40))
        state["updated_at"] = dt.datetime.now(dt.UTC).isoformat()

    def finish(self, scan_id: int, status: str, payload: dict[str, Any] | None = None) -> None:
        state = self._state.setdefault(scan_id, {})
        state.update(
            {
                "status": status,
                "stage": "Assessment complete" if status == "completed" else "Assessment failed",
                "percent": 100,
                "updated_at": dt.datetime.now(dt.UTC).isoformat(),
                **(payload or {}),
            }
        )

    def snapshot(self, scan_id: int) -> dict[str, Any] | None:
        state = self._state.get(scan_id)
        return dict(state) if state else None


class ScanQueue:
    def __init__(self, session_factory: async_sessionmaker[AsyncSession], hub: ProgressHub, concurrency: int = 2) -> None:
        self.session_factory = session_factory
        self.hub = hub
        self.semaphore = asyncio.Semaphore(concurrency)
        self.tasks: dict[int, asyncio.Task[None]] = {}

    def enqueue(self, scan_id: int, url: str, config: ScanConfig) -> None:
        self.hub.initialize(scan_id, config)
        self.tasks[scan_id] = asyncio.create_task(self._run(scan_id, url, config))

    def cancel(self, scan_id: int) -> None:
        task = self.tasks.pop(scan_id, None)
        if task is not None and not task.done():
            task.cancel()

    async def _run(self, scan_id: int, url: str, config: ScanConfig) -> None:
        async with self.semaphore:
            self.hub.start(scan_id)
            await self.hub.publish(scan_id, "started")
            async with self.session_factory() as session:
                repo = AssessmentRepository(session)
                await repo.update_scan_status(scan_id, ScanStatus.RUNNING)
                await session.commit()
            try:
                scanner = Scanner(config)

                async def record_event(event: ScannerEvent) -> None:
                    self.hub.record_scanner_event(scan_id, event)
                    await self.hub.publish(scan_id, "progress", self.hub.snapshot(scan_id) or {})

                for event_type in EventType:
                    scanner.events.subscribe(event_type, record_event)

                reports = await scanner.scan([url])
                report = reports[0]
                async with self.session_factory() as session:
                    repo = AssessmentRepository(session)
                    await repo.persist_target_report(scan_id, report)
                    await session.flush()
                    scan = await repo.get_scan(scan_id)
                    if scan is None:
                        raise RuntimeError(f"scan {scan_id} disappeared during persistence")
                    service = ReportService()
                    external = service.build_external(scan)
                    internal = service.build_internal(scan)
                    await repo.add_report(scan_id, "external", "html", "External Security Assessment", body=external.html)
                    await repo.add_report(scan_id, "external", "markdown", "External Security Assessment", body=external.markdown)
                    await repo.add_report(scan_id, "internal", "html", "Internal Remediation Report", body=internal.html)
                    await repo.add_report(scan_id, "internal", "markdown", "Internal Remediation Report", body=internal.markdown)
                    await session.commit()
                self.hub.finish(scan_id, "completed", {"findings": len(report.findings), "pages": report.pages_crawled})
                await self.hub.publish(scan_id, "completed", {"findings": len(report.findings), "pages": report.pages_crawled})
            except Exception as exc:
                async with self.session_factory() as session:
                    repo = AssessmentRepository(session)
                    await repo.update_scan_status(scan_id, ScanStatus.FAILED, str(exc))
                    await session.commit()
                self.hub.finish(scan_id, "failed", {"error": str(exc)})
                await self.hub.publish(scan_id, "failed", {"error": str(exc)})


def scan_config_from_payload(payload: ScanCreate, out_dir: Path) -> ScanConfig:
    return ScanConfig(
        out_dir=out_dir,
        max_depth=payload.max_depth,
        max_pages=payload.max_pages,
        request_budget=max(int(getattr(payload, "request_budget", 40)), 1),
        enable_browser_checks=payload.enable_browser,
        enable_active_checks=payload.enable_active_checks,
        capture_screenshots=payload.capture_screenshots,
        enable_attack_surface_expansion=bool(getattr(payload, "enable_attack_surface_expansion", True)),
        enable_framework_expansion=bool(getattr(payload, "enable_framework_expansion", True)),
        enable_predictable_locations=bool(getattr(payload, "enable_predictable_locations", True)),
        enable_api_expansion=bool(getattr(payload, "enable_api_expansion", True)),
        enable_runtime_expansion=bool(getattr(payload, "enable_runtime_expansion", True)),
        expansion_max_candidates=max(int(getattr(payload, "expansion_max_candidates", 50)), 1),
        expansion_probe_budget=max(int(getattr(payload, "expansion_probe_budget", 25)), 0),
        expansion_min_confidence=max(0.0, min(float(getattr(payload, "expansion_min_confidence", 0.35)), 1.0)),
    )


def _expected_work(config: ScanConfig) -> int:
    base = max(int(config.max_pages), 1)
    base += max(int(config.request_budget), 1)
    if config.enable_browser_checks:
        base += max(int(config.browser_route_budget), 1) + max(int(config.browser_api_budget), 1)
    if config.enable_attack_surface_expansion:
        base += max(int(config.expansion_probe_budget), 1)
    return max(base, 20)


def _event_percent(events: dict[str, int], expected_work: int) -> int:
    weighted = (
        events.get(EventType.RESPONSE_RECEIVED.value, 0)
        + events.get(EventType.JS_DISCOVERED.value, 0)
        + events.get(EventType.URL_DISCOVERED.value, 0)
        + events.get(EventType.PARAMETER_FOUND.value, 0) // 2
        + events.get(EventType.FORM_FOUND.value, 0)
        + events.get(EventType.FINDING_CREATED.value, 0) * 2
    )
    return min(94, 18 + round((weighted / max(expected_work, 1)) * 76))


def _stage_from_event(event: ScannerEvent) -> str:
    if event.type == EventType.RESPONSE_RECEIVED:
        return "Fetching and analyzing pages"
    if event.type == EventType.JS_DISCOVERED:
        return "Inspecting JavaScript assets"
    if event.type == EventType.URL_DISCOVERED:
        return "Expanding discovered URLs"
    if event.type == EventType.PARAMETER_FOUND:
        return "Mapping request parameters"
    if event.type == EventType.FORM_FOUND:
        return "Cataloging forms and inputs"
    if event.type == EventType.FINDING_CREATED:
        return "Recording findings"
    return "Assessment in progress"


def _event_line(event: ScannerEvent) -> str:
    value = event.payload.get("url") or event.payload.get("source") or event.payload.get("finding") or event.payload.get("parameter") or event.type.value
    return f"{event.type.value}: {value}"
