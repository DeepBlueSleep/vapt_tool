from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from scanner.core.models import Finding, Page, TargetReport


@dataclass(frozen=True)
class PluginMetadata:
    name: str
    version: str
    description: str
    category: str
    active: bool = False


class ScannerPlugin(Protocol):
    metadata: PluginMetadata

    async def analyze(self, page: Page, report: TargetReport) -> list[Finding]:
        ...
