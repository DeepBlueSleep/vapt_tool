from __future__ import annotations

import datetime as dt
from enum import StrEnum
from typing import Any

from sqlalchemy import DateTime, Float, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.dialects.sqlite import JSON
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


class ScanStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class FindingState(StrEnum):
    NEW = "new"
    TRIAGED = "triaged"
    ACCEPTED = "accepted"
    RESOLVED = "resolved"
    SUPPRESSED = "suppressed"


class ReportAudience(StrEnum):
    EXTERNAL = "external"
    INTERNAL = "internal"
    DEVELOPER = "developer"
    COMPLIANCE = "compliance"


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    target_url: Mapped[str] = mapped_column(String(2048), index=True)
    status: Mapped[str] = mapped_column(String(32), default=ScanStatus.QUEUED.value, index=True)
    owner: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=lambda: dt.datetime.now(dt.UTC), index=True)
    started_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    posture_score: Mapped[float] = mapped_column(Float, default=0.0)
    posture_grade: Mapped[str] = mapped_column(String(4), default="n/a")
    pages_crawled: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    config: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    inventory: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)

    findings: Mapped[list[Finding]] = relationship(back_populates="scan", cascade="all, delete-orphan")
    evidence: Mapped[list[Evidence]] = relationship(back_populates="scan", cascade="all, delete-orphan")
    reports: Mapped[list[ReportArtifact]] = relationship(back_populates="scan", cascade="all, delete-orphan")
    metrics: Mapped[list[Metric]] = relationship(back_populates="scan", cascade="all, delete-orphan")
    routes: Mapped[list[Route]] = relationship(back_populates="scan", cascade="all, delete-orphan")
    runtime_apis: Mapped[list[RuntimeApi]] = relationship(back_populates="scan", cascade="all, delete-orphan")
    parameters: Mapped[list[Parameter]] = relationship(back_populates="scan", cascade="all, delete-orphan")
    auth_signals: Mapped[list[AuthSignal]] = relationship(back_populates="scan", cascade="all, delete-orphan")


class Finding(Base):
    __tablename__ = "findings"
    __table_args__ = (UniqueConstraint("scan_id", "dedup_key", name="uq_findings_scan_dedup"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), index=True)
    scanner_finding_id: Mapped[str] = mapped_column(String(255), index=True)
    dedup_key: Mapped[str] = mapped_column(String(1024), index=True)
    title: Mapped[str] = mapped_column(String(512), index=True)
    severity: Mapped[str] = mapped_column(String(32), index=True)
    classification: Mapped[str] = mapped_column(String(64), index=True)
    confidence: Mapped[str] = mapped_column(String(32))
    state: Mapped[str] = mapped_column(String(32), default=FindingState.NEW.value, index=True)
    owner: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    url: Mapped[str] = mapped_column(String(2048))
    scope: Mapped[str] = mapped_column(String(64))
    evidence_summary: Mapped[str] = mapped_column(Text)
    remediation: Mapped[str] = mapped_column(Text)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0, index=True)
    occurrence_count: Mapped[int] = mapped_column(Integer, default=1)
    affected_resources: Mapped[list[str]] = mapped_column(JSON, default=list)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    first_seen_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=lambda: dt.datetime.now(dt.UTC), index=True)
    resolved_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    scan: Mapped[Scan] = relationship(back_populates="findings")
    evidence: Mapped[list[Evidence]] = relationship(back_populates="finding")


class Evidence(Base):
    __tablename__ = "evidence"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), index=True)
    finding_id: Mapped[int | None] = mapped_column(ForeignKey("findings.id"), nullable=True, index=True)
    kind: Mapped[str] = mapped_column(String(64), index=True)
    title: Mapped[str] = mapped_column(String(512))
    content_type: Mapped[str] = mapped_column(String(128), default="text/plain")
    storage_path: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    summary: Mapped[str] = mapped_column(Text, default="")
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=lambda: dt.datetime.now(dt.UTC))

    scan: Mapped[Scan] = relationship(back_populates="evidence")
    finding: Mapped[Finding | None] = relationship(back_populates="evidence")


class ReportArtifact(Base):
    __tablename__ = "report_artifacts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), index=True)
    audience: Mapped[str] = mapped_column(String(32), index=True)
    format: Mapped[str] = mapped_column(String(32), index=True)
    title: Mapped[str] = mapped_column(String(512))
    storage_path: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    body: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=lambda: dt.datetime.now(dt.UTC), index=True)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)

    scan: Mapped[Scan] = relationship(back_populates="reports")


class Metric(Base):
    __tablename__ = "metrics"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), index=True)
    name: Mapped[str] = mapped_column(String(255), index=True)
    value: Mapped[float] = mapped_column(Float)

    scan: Mapped[Scan] = relationship(back_populates="metrics")


class Route(Base):
    __tablename__ = "routes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), index=True)
    url: Mapped[str] = mapped_column(String(2048), index=True)
    source: Mapped[str] = mapped_column(String(128), default="crawler")
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)

    scan: Mapped[Scan] = relationship(back_populates="routes")


class RuntimeApi(Base):
    __tablename__ = "runtime_apis"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), index=True)
    method: Mapped[str] = mapped_column(String(16), default="GET")
    url: Mapped[str] = mapped_column(String(2048), index=True)
    kind: Mapped[str] = mapped_column(String(64), default="unknown")
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)

    scan: Mapped[Scan] = relationship(back_populates="runtime_apis")


class Parameter(Base):
    __tablename__ = "parameters"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), index=True)
    name: Mapped[str] = mapped_column(String(255), index=True)
    source: Mapped[str] = mapped_column(String(2048))
    method: Mapped[str] = mapped_column(String(16), default="GET")
    param_type: Mapped[str] = mapped_column(String(64), default="unknown")

    scan: Mapped[Scan] = relationship(back_populates="parameters")


class AuthSignal(Base):
    __tablename__ = "auth_signals"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), index=True)
    kind: Mapped[str] = mapped_column(String(128), index=True)
    url: Mapped[str] = mapped_column(String(2048))
    confidence: Mapped[float] = mapped_column(Float, default=0.0)

    scan: Mapped[Scan] = relationship(back_populates="auth_signals")
