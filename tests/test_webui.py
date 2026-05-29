import importlib.util
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(
    any(importlib.util.find_spec(package) is None for package in ("fastapi", "sqlalchemy", "jinja2", "multipart")),
    reason="web UI optional dependencies are not installed",
)


def test_webui_dashboard_renders(tmp_path: Path) -> None:
    from platform.api.app import create_app

    from fastapi.testclient import TestClient

    app = create_app(f"sqlite+aiosqlite:///{tmp_path / 'webui.db'}")
    app.state.output_dir = tmp_path / "artifacts"

    with TestClient(app) as client:
        response = client.get("/")

    assert response.status_code == 200
    assert "Start Scan" in response.text
    assert "Recent Scans" in response.text


def test_webui_results_routes_render_persisted_scan(tmp_path: Path) -> None:
    import asyncio
    from platform.api.app import create_app
    from platform.database.models import Finding
    from platform.database.repository import AssessmentRepository

    from fastapi.testclient import TestClient

    app = create_app(f"sqlite+aiosqlite:///{tmp_path / 'webui-results.db'}")
    app.state.output_dir = tmp_path / "artifacts"

    async def seed_scan() -> int:
        async with app.state.session_factory() as session:
            repo = AssessmentRepository(session)
            scan = await repo.create_scan("https://example.com", config={"source": "test"})
            scan.status = "completed"
            scan.posture_grade = "B"
            scan.posture_score = 82.0
            scan.inventory = {"runtime_apis": ["GET rest https://example.com/api"], "pages": ["https://example.com/"]}
            session.add(
                Finding(
                    scan_id=scan.id,
                    scanner_finding_id="f1",
                    dedup_key="f1",
                    title="Missing Content Security Policy",
                    severity="medium",
                    classification="recommendation",
                    confidence="high",
                    url="https://example.com/",
                    scope="host",
                    evidence_summary="content-security-policy header was not present.",
                    remediation="Add a restrictive Content-Security-Policy header.",
                    risk_score=55.0,
                )
            )
            await session.commit()
            return scan.id

    with TestClient(app) as client:
        scan_id = asyncio.run(seed_scan())
        results = client.get(f"/reports/{scan_id}")
        external = client.get(f"/reports/{scan_id}/external")
        internal = client.get(f"/reports/{scan_id}/internal")

    assert results.status_code == 200
    assert "Finding" in results.text
    assert "Attack Surface Explorer" in results.text
    assert external.status_code == 200
    assert "External Security Assessment" in external.text
    assert internal.status_code == 200
    assert "Internal Remediation Report" in internal.text


def test_pdf_download_disables_http_cache(tmp_path: Path) -> None:
    import asyncio
    from platform.api.app import create_app
    from platform.database.models import ReportArtifact
    from platform.database.repository import AssessmentRepository

    from fastapi.testclient import TestClient

    pdf_path = tmp_path / "artifacts" / "scan-1" / "internal.pdf"
    pdf_path.parent.mkdir(parents=True)
    pdf_path.write_bytes(b"%PDF-1.4\n% test\n")
    app = create_app(f"sqlite+aiosqlite:///{tmp_path / 'webui-pdf-cache.db'}")
    app.state.output_dir = tmp_path / "artifacts"

    async def seed_scan() -> int:
        async with app.state.session_factory() as session:
            repo = AssessmentRepository(session)
            scan = await repo.create_scan("https://example.com", config={"source": "test"})
            scan.status = "completed"
            scan.posture_grade = "A"
            scan.inventory = {}
            session.add(
                ReportArtifact(
                    scan_id=scan.id,
                    audience="internal",
                    format="pdf",
                    title="Internal PDF",
                    storage_path=str(pdf_path),
                    metadata_json={"renderer_version": "2026-05-webui-styled-pdf-v4", "renderer": "styled"},
                )
            )
            await session.commit()
            return scan.id

    with TestClient(app) as client:
        scan_id = asyncio.run(seed_scan())
        response = client.get(f"/reports/{scan_id}/internal.pdf")

    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store, no-cache, must-revalidate, max-age=0"


def test_webui_can_delete_old_scans_and_artifacts(tmp_path: Path) -> None:
    import asyncio
    from platform.api.app import create_app
    from platform.database.repository import AssessmentRepository

    from fastapi.testclient import TestClient

    artifacts = tmp_path / "artifacts"
    app = create_app(f"sqlite+aiosqlite:///{tmp_path / 'webui-delete.db'}")
    app.state.output_dir = artifacts

    async def seed_scan() -> int:
        async with app.state.session_factory() as session:
            repo = AssessmentRepository(session)
            scan = await repo.create_scan("https://example.com", config={"source": "test"})
            scan.status = "completed"
            await session.commit()
            return scan.id

    async def scan_count() -> int:
        async with app.state.session_factory() as session:
            repo = AssessmentRepository(session)
            return len(await repo.list_scans(limit=100))

    with TestClient(app) as client:
        scan_id = asyncio.run(seed_scan())
        scan_dir = artifacts / f"scan-{scan_id}"
        scan_dir.mkdir(parents=True)
        (scan_dir / "internal.pdf").write_bytes(b"%PDF-1.4\n")

        response = client.post(f"/scan/{scan_id}/delete", follow_redirects=False)

    assert response.status_code == 303
    assert asyncio.run(scan_count()) == 0
    assert not scan_dir.exists()


def test_webui_can_delete_all_scans(tmp_path: Path) -> None:
    import asyncio
    from platform.api.app import create_app
    from platform.database.repository import AssessmentRepository

    from fastapi.testclient import TestClient

    artifacts = tmp_path / "artifacts"
    app = create_app(f"sqlite+aiosqlite:///{tmp_path / 'webui-delete-all.db'}")
    app.state.output_dir = artifacts

    async def seed_scans() -> list[int]:
        async with app.state.session_factory() as session:
            repo = AssessmentRepository(session)
            first = await repo.create_scan("https://one.example", config={"source": "test"})
            second = await repo.create_scan("https://two.example", config={"source": "test"})
            await session.commit()
            return [first.id, second.id]

    async def scan_count() -> int:
        async with app.state.session_factory() as session:
            repo = AssessmentRepository(session)
            return len(await repo.list_scans(limit=100))

    with TestClient(app) as client:
        scan_ids = asyncio.run(seed_scans())
        for scan_id in scan_ids:
            scan_dir = artifacts / f"scan-{scan_id}"
            scan_dir.mkdir(parents=True)
            (scan_dir / "external.pdf").write_bytes(b"%PDF-1.4\n")

        response = client.post("/scans/delete", follow_redirects=False)

    assert response.status_code == 303
    assert asyncio.run(scan_count()) == 0
    assert all(not (artifacts / f"scan-{scan_id}").exists() for scan_id in scan_ids)
