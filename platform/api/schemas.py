from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field, HttpUrl


class ScanCreate(BaseModel):
    url: HttpUrl
    max_depth: int = Field(default=1, ge=0, le=5)
    max_pages: int = Field(default=25, ge=1, le=500)
    enable_browser: bool = False
    enable_active_checks: bool = False
    capture_screenshots: bool = False
    request_budget: int = Field(default=40, ge=1, le=1000)
    report_mode: str = "external"
    enable_attack_surface_expansion: bool = True
    enable_framework_expansion: bool = True
    enable_predictable_locations: bool = True
    enable_api_expansion: bool = True
    enable_runtime_expansion: bool = True
    expansion_max_candidates: int = Field(default=50, ge=1, le=250)
    expansion_probe_budget: int = Field(default=25, ge=0, le=100)
    expansion_min_confidence: float = Field(default=0.35, ge=0.0, le=1.0)
    owner: str | None = None


class ScanCreated(BaseModel):
    id: int
    status: str
    websocket_url: str


class PdfExportRequest(BaseModel):
    scan_id: int
    audience: Literal["external", "internal", "developer", "compliance"] = "external"


class ScanResponse(BaseModel):
    id: int
    target_url: str
    status: str
    owner: str | None = None
    posture_score: float
    posture_grade: str
    pages_crawled: int
    error: str | None = None
    inventory: dict[str, Any] = Field(default_factory=dict)
    findings: list[dict[str, Any]] = Field(default_factory=list)
    evidence: list[dict[str, Any]] = Field(default_factory=list)
    reports: list[dict[str, Any]] = Field(default_factory=list)
