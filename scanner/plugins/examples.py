from __future__ import annotations

from scanner.core.models import Finding, Page, TargetReport
from scanner.plugins.base import PluginMetadata


class ExamplePassivePlugin:
    metadata = PluginMetadata(
        name="example.passive",
        version="1.0",
        description="Minimal plugin template for passive analysis.",
        category="passive",
    )

    async def analyze(self, _page: Page, _report: TargetReport) -> list[Finding]:
        return []
