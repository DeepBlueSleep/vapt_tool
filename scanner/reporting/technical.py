from __future__ import annotations

from scanner.core.models import ScanResult
from scanner.reporting.reports import render_markdown


def render_technical_markdown(result: ScanResult) -> str:
    return render_markdown(result)
