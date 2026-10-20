import os
import shutil
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from pathlib import Path
from platform.api.queue import ProgressHub, ScanQueue, scan_config_from_payload
from platform.api.schemas import PdfExportRequest, ScanCreate, ScanCreated
from platform.dashboards.analytics import build_dashboard_summary
from platform.database.migrations import migrate
from platform.database.models import ReportAudience
from platform.database.repository import AssessmentRepository, serialize_finding, serialize_scan
from platform.exports.pdf.service import PdfExportService
from platform.reporting.service import ReportService
from platform.webui import register_webui
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, Response, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine


def create_app(database_url: str | None = None) -> FastAPI:
    db_url: str = database_url or os.getenv("ASSESSMENT_DATABASE_URL") or "sqlite+aiosqlite:///./platform.db"
    output_dir = Path(os.getenv("ASSESSMENT_OUTPUT_DIR", "platform-data"))
    engine = create_async_engine(db_url, future=True)
    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    hub = ProgressHub()
    queue = ScanQueue(session_factory, hub)

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncGenerator[None]:
        await migrate(engine)
        output_dir.mkdir(parents=True, exist_ok=True)
        try:
            yield
        finally:
            await engine.dispose()

    app = FastAPI(
        title="Runtime-Aware Security Assessment Platform",
        version="0.1.0",
        description="Async assessment backend for scans, evidence, reports, exports, history, and posture tracking.",
        lifespan=lifespan,
    )
    app.state.session_factory = session_factory
    app.state.scan_queue = queue
    app.state.progress_hub = hub
    app.state.output_dir = output_dir
    app.add_middleware(
        CORSMiddleware,
        allow_origins=os.getenv("ASSESSMENT_CORS_ORIGINS", "*").split(","),
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    async def get_session() -> AsyncGenerator[AsyncSession]:
        async with session_factory() as session:
            yield session

    SessionDep = Annotated[AsyncSession, Depends(get_session)]

    @app.post("/scans", response_model=ScanCreated)
    async def create_scan(payload: ScanCreate, session: SessionDep) -> ScanCreated:
        repo = AssessmentRepository(session)
        scan = await repo.create_scan(str(payload.url), config=payload.model_dump(mode="json"), owner=payload.owner)
        await session.commit()
        config = scan_config_from_payload(payload, output_dir / f"scan-{scan.id}")
        queue.enqueue(scan.id, scan.target_url, config)
        return ScanCreated(id=scan.id, status=scan.status, websocket_url=f"/scans/{scan.id}/progress")

    @app.get("/scans")
    async def list_scans(session: SessionDep) -> list[dict[str, object]]:
        repo = AssessmentRepository(session)
        scans = await repo.list_scans()
        return [serialize_scan(scan) for scan in scans]

    @app.get("/scans/{scan_id}")
    async def get_scan(scan_id: int, session: SessionDep) -> dict[str, object]:
        repo = AssessmentRepository(session)
        scan = await repo.get_scan(scan_id)
        if scan is None:
            raise HTTPException(status_code=404, detail="scan not found")
        return serialize_scan(scan)

    @app.delete("/scans/{scan_id}", status_code=204)
    async def delete_scan(scan_id: int, session: SessionDep) -> Response:
        repo = AssessmentRepository(session)
        scan = await repo.get_scan(scan_id)
        if scan is None:
            raise HTTPException(status_code=404, detail="scan not found")
        queue.cancel(scan_id)
        cleanup_paths = _scan_artifact_paths(output_dir, scan_id)
        deleted = await repo.delete_scan(scan_id)
        if not deleted:
            raise HTTPException(status_code=404, detail="scan not found")
        await session.commit()
        _remove_paths(cleanup_paths)
        return Response(status_code=204)

    @app.delete("/scans", status_code=204)
    async def delete_scans(session: SessionDep) -> Response:
        repo = AssessmentRepository(session)
        scans = await repo.list_scans(limit=10_000)
        cleanup_paths = [_scan_artifact_paths(output_dir, scan.id) for scan in scans]
        for scan in scans:
            queue.cancel(scan.id)
        await repo.delete_scans([scan.id for scan in scans])
        await session.commit()
        for paths in cleanup_paths:
            _remove_paths(paths)
        return Response(status_code=204)

    @app.websocket("/scans/{scan_id}/progress")
    async def progress(scan_id: int, websocket: WebSocket) -> None:
        await hub.connect(scan_id, websocket)
        try:
            await websocket.send_json({"scan_id": scan_id, "event": "connected", "payload": {}})
            while True:
                await websocket.receive_text()
        except WebSocketDisconnect:
            hub.disconnect(scan_id, websocket)

    @app.get("/findings/{finding_id}")
    async def get_finding(finding_id: int, session: SessionDep) -> dict[str, object]:
        repo = AssessmentRepository(session)
        finding = await repo.get_finding(finding_id)
        if finding is None:
            raise HTTPException(status_code=404, detail="finding not found")
        return serialize_finding(finding)

    @app.get("/api/reports/{report_id}")
    async def get_report(report_id: int, session: SessionDep) -> Response:
        repo = AssessmentRepository(session)
        report = await repo.get_report(report_id)
        if report is None:
            raise HTTPException(status_code=404, detail="report not found")
        media_type = "text/html" if report.format == "html" else "text/markdown" if report.format == "markdown" else "application/json"
        return Response(content=report.body or "", media_type=media_type)

    @app.post("/exports/pdf")
    async def export_pdf(payload: PdfExportRequest, session: SessionDep) -> dict[str, object]:
        repo = AssessmentRepository(session)
        scan = await repo.get_scan(payload.scan_id)
        if scan is None:
            raise HTTPException(status_code=404, detail="scan not found")
        service = ReportService()
        bundle = service.build_internal(scan) if payload.audience != ReportAudience.EXTERNAL.value else service.build_external(scan)
        output = output_dir / f"scan-{scan.id}" / f"{payload.audience}.pdf"
        output.unlink(missing_ok=True)
        try:
            path = await PdfExportService().render_pdf(bundle.html, output)
        except RuntimeError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        artifact = await repo.add_report(scan.id, payload.audience, "pdf", f"{payload.audience.title()} PDF", storage_path=str(path))
        await session.commit()
        return {"report_id": artifact.id, "path": str(path)}

    @app.get("/metrics")
    async def metrics(session: SessionDep) -> dict[str, object]:
        repo = AssessmentRepository(session)
        scans = await repo.list_scans(limit=100)
        summary = await repo.metrics_summary()
        summary["dashboard"] = build_dashboard_summary(scans)
        return summary

    @app.get("/history")
    async def history(session: SessionDep, target_url: str | None = None) -> list[dict[str, object]]:
        repo = AssessmentRepository(session)
        return await repo.history(target_url=target_url)

    @app.get("/compare")
    async def compare(previous_id: int, current_id: int, session: SessionDep) -> dict[str, list[str]]:
        repo = AssessmentRepository(session)
        try:
            return await repo.compare_scans(previous_id, current_id)
        except ValueError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    register_webui(app)
    return app


app = create_app()


def _scan_artifact_paths(output_dir: Path, scan_id: int) -> list[Path]:
    return [output_dir / f"scan-{scan_id}"]


def _remove_paths(paths: list[Path]) -> None:
    for path in paths:
        try:
            if path.is_dir():
                shutil.rmtree(path)
            elif path.exists():
                path.unlink()
        except OSError:
            continue
