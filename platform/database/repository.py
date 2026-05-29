from __future__ import annotations

import datetime as dt
from platform.database.models import (
    AuthSignal,
    Evidence,
    Finding,
    Metric,
    Parameter,
    ReportArtifact,
    Route,
    RuntimeApi,
    Scan,
    ScanStatus,
)
from typing import Any, cast

from sqlalchemy import Select, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from scanner.core.models import TargetReport
from scanner.risk.posture import score_posture


class AssessmentRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def create_scan(self, target_url: str, config: dict[str, Any] | None = None, owner: str | None = None) -> Scan:
        scan = Scan(target_url=target_url, config=config or {}, owner=owner, status=ScanStatus.QUEUED.value)
        self.session.add(scan)
        await self.session.flush()
        return scan

    async def update_scan_status(self, scan_id: int, status: ScanStatus, error: str | None = None) -> None:
        scan = await self.session.get(Scan, scan_id)
        if scan is None:
            return
        scan.status = status.value
        scan.error = error
        now = dt.datetime.now(dt.UTC)
        if status == ScanStatus.RUNNING:
            scan.started_at = now
        if status in {ScanStatus.COMPLETED, ScanStatus.FAILED, ScanStatus.CANCELLED}:
            scan.completed_at = now
        await self.session.flush()

    async def persist_target_report(self, scan_id: int, report: TargetReport) -> Scan:
        scan = await self.session.get(Scan, scan_id)
        if scan is None:
            raise ValueError(f"scan {scan_id} does not exist")
        posture = score_posture(report)
        scan.status = ScanStatus.COMPLETED.value
        scan.completed_at = dt.datetime.now(dt.UTC)
        scan.pages_crawled = report.pages_crawled
        scan.posture_score = posture.score
        scan.posture_grade = posture.grade
        scan.inventory = report.inventory
        scan.error = "; ".join(report.errors) if report.errors else None
        for finding in report.findings:
            self.session.add(
                Finding(
                    scan_id=scan_id,
                    scanner_finding_id=finding.id,
                    dedup_key=finding.normalized_key(),
                    title=finding.title,
                    severity=finding.severity.value,
                    classification=finding.classification.value,
                    confidence=finding.confidence.value,
                    url=finding.url,
                    scope=finding.scope.value,
                    evidence_summary=finding.evidence,
                    remediation=finding.remediation,
                    risk_score=finding.risk_score,
                    occurrence_count=finding.occurrence_count,
                    affected_resources=finding.affected_resources,
                    metadata_json=finding.metadata,
                )
            )
        for name, value in report.metrics.items():
            if isinstance(value, int | float):
                self.session.add(Metric(scan_id=scan_id, name=name, value=float(value)))
        self._persist_inventory(scan_id, report.inventory)
        await self.session.flush()
        return scan

    def _persist_inventory(self, scan_id: int, inventory: dict[str, list[str]]) -> None:
        for url in inventory.get("pages", []) + inventory.get("browser_routes", []):
            self.session.add(Route(scan_id=scan_id, url=url, source="runtime" if url in inventory.get("browser_routes", []) else "crawler"))
        for item in inventory.get("runtime_apis", []) + inventory.get("endpoints", []):
            parts = item.split(" ", 2)
            method = parts[0] if parts else "GET"
            kind = parts[1] if len(parts) > 2 else "unknown"
            url = parts[2] if len(parts) > 2 else item
            self.session.add(RuntimeApi(scan_id=scan_id, method=method, kind=kind, url=url))
        for item in inventory.get("parameters", []) + inventory.get("runtime_parameters", []):
            method, name = ("GET", item)
            if " " in item:
                method, name = item.split(" ", 1)
            self.session.add(Parameter(scan_id=scan_id, method=method[:16], name=name[:255], source=item))
        for item in inventory.get("auth_signals", []):
            parts = item.split(" ")
            kind = parts[0] if parts else "unknown"
            confidence = float(parts[1]) if len(parts) > 1 and _is_float(parts[1]) else 0.0
            url = parts[-1] if parts else ""
            self.session.add(AuthSignal(scan_id=scan_id, kind=kind, confidence=confidence, url=url))
        for path in inventory.get("screenshots", []):
            self.session.add(
                Evidence(
                    scan_id=scan_id,
                    kind="screenshot",
                    title="Browser screenshot",
                    storage_path=path,
                    content_type="image/png",
                )
            )

    async def add_report(
        self,
        scan_id: int,
        audience: str,
        fmt: str,
        title: str,
        body: str | None = None,
        storage_path: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> ReportArtifact:
        artifact = ReportArtifact(
            scan_id=scan_id,
            audience=audience,
            format=fmt,
            title=title,
            body=body,
            storage_path=storage_path,
            metadata_json=metadata or {},
        )
        self.session.add(artifact)
        await self.session.flush()
        return artifact

    async def list_scans(self, limit: int = 50) -> list[Scan]:
        statement = (
            select(Scan)
            .order_by(Scan.created_at.desc())
            .limit(limit)
            .options(selectinload(Scan.findings), selectinload(Scan.evidence), selectinload(Scan.reports))
        )
        return list((await self.session.scalars(statement)).all())

    async def get_scan(self, scan_id: int) -> Scan | None:
        statement: Select[tuple[Scan]] = (
            select(Scan)
            .where(Scan.id == scan_id)
            .options(
                selectinload(Scan.findings),
                selectinload(Scan.evidence),
                selectinload(Scan.reports),
                selectinload(Scan.metrics),
                selectinload(Scan.routes),
                selectinload(Scan.runtime_apis),
                selectinload(Scan.parameters),
                selectinload(Scan.auth_signals),
            )
        )
        return cast(Scan | None, await self.session.scalar(statement))

    async def delete_scan(self, scan_id: int) -> bool:
        scan = await self.get_scan(scan_id)
        if scan is None:
            return False
        await self.session.delete(scan)
        await self.session.flush()
        return True

    async def delete_scans(self, scan_ids: list[int] | None = None) -> int:
        statement = select(Scan)
        if scan_ids is not None:
            if not scan_ids:
                return 0
            statement = statement.where(Scan.id.in_(scan_ids))
        scans = list((await self.session.scalars(statement)).all())
        for scan in scans:
            await self.session.delete(scan)
        await self.session.flush()
        return len(scans)

    async def get_finding(self, finding_id: int) -> Finding | None:
        return await self.session.get(Finding, finding_id)

    async def get_report(self, report_id: int) -> ReportArtifact | None:
        return await self.session.get(ReportArtifact, report_id)

    async def metrics_summary(self) -> dict[str, Any]:
        total_scans = await self.session.scalar(select(func.count(Scan.id)))
        open_findings = await self.session.scalar(select(func.count(Finding.id)).where(Finding.state != "resolved"))
        by_severity = {}
        severity_counts = await self.session.execute(select(Finding.severity, func.count(Finding.id)).group_by(Finding.severity))
        for severity, count in severity_counts.all():
            by_severity[severity] = count
        return {"scans": total_scans or 0, "open_findings": open_findings or 0, "by_severity": by_severity}

    async def history(self, target_url: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
        statement = select(Scan).order_by(Scan.created_at.desc()).limit(limit)
        if target_url:
            statement = statement.where(Scan.target_url == target_url)
        scans = (await self.session.scalars(statement)).all()
        return [
            {
                "id": scan.id,
                "target_url": scan.target_url,
                "status": scan.status,
                "created_at": scan.created_at.isoformat(),
                "posture_score": scan.posture_score,
                "posture_grade": scan.posture_grade,
                "pages_crawled": scan.pages_crawled,
            }
            for scan in scans
        ]

    async def compare_scans(self, previous_id: int, current_id: int) -> dict[str, list[str]]:
        previous = await self.get_scan(previous_id)
        current = await self.get_scan(current_id)
        if previous is None or current is None:
            raise ValueError("both scans must exist")
        old = {finding.dedup_key: finding.title for finding in previous.findings}
        new = {finding.dedup_key: finding.title for finding in current.findings}
        return {
            "introduced": [new[key] for key in sorted(new.keys() - old.keys())],
            "resolved": [old[key] for key in sorted(old.keys() - new.keys())],
            "persistent": [new[key] for key in sorted(new.keys() & old.keys())],
        }


def serialize_scan(scan: Scan) -> dict[str, Any]:
    return {
        "id": scan.id,
        "target_url": scan.target_url,
        "status": scan.status,
        "owner": scan.owner,
        "created_at": scan.created_at.isoformat(),
        "started_at": scan.started_at.isoformat() if scan.started_at else None,
        "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
        "posture_score": scan.posture_score,
        "posture_grade": scan.posture_grade,
        "pages_crawled": scan.pages_crawled,
        "error": scan.error,
        "inventory": scan.inventory,
        "findings": [serialize_finding(finding) for finding in getattr(scan, "findings", [])],
        "evidence": [serialize_evidence(evidence) for evidence in getattr(scan, "evidence", [])],
        "reports": [serialize_report(report) for report in getattr(scan, "reports", [])],
    }


def serialize_finding(finding: Finding) -> dict[str, Any]:
    return {
        "id": finding.id,
        "scan_id": finding.scan_id,
        "title": finding.title,
        "severity": finding.severity,
        "classification": finding.classification,
        "confidence": finding.confidence,
        "state": finding.state,
        "owner": finding.owner,
        "url": finding.url,
        "scope": finding.scope,
        "evidence_summary": finding.evidence_summary,
        "remediation": finding.remediation,
        "risk_score": finding.risk_score,
        "occurrence_count": finding.occurrence_count,
        "affected_resources": finding.affected_resources,
        "metadata": finding.metadata_json,
    }


def serialize_evidence(evidence: Evidence) -> dict[str, Any]:
    return {
        "id": evidence.id,
        "scan_id": evidence.scan_id,
        "finding_id": evidence.finding_id,
        "kind": evidence.kind,
        "title": evidence.title,
        "content_type": evidence.content_type,
        "storage_path": evidence.storage_path,
        "summary": evidence.summary,
        "metadata": evidence.metadata_json,
    }


def serialize_report(report: ReportArtifact) -> dict[str, Any]:
    return {
        "id": report.id,
        "scan_id": report.scan_id,
        "audience": report.audience,
        "format": report.format,
        "title": report.title,
        "storage_path": report.storage_path,
        "created_at": report.created_at.isoformat(),
        "metadata": report.metadata_json,
    }


def _is_float(value: str) -> bool:
    try:
        float(value)
    except ValueError:
        return False
    return True
