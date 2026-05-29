from __future__ import annotations

from scanner.core.models import ScanResult
from scanner.reporting.vapt import render_vapt_html


def render_modern_html(result: ScanResult, mode: str = "technical") -> str:
    audience = "external" if mode == "executive" else "internal"
    return render_vapt_html(result, audience=audience)
