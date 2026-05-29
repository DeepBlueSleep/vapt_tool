from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class CveMatch:
    cve_id: str
    cvss: float | None
    epss: float | None
    summary: str
    references: tuple[str, ...]


class CveEnricher:
    """CVE enrichment seam with local caching and async workers planned.

    Network-backed NVD/EPSS lookups are deliberately disabled unless the user
    opts in. The core scanner can call this class without changing check logic.
    """

    async def enrich_technology(self, _name: str, _version: str | None) -> list[CveMatch]:
        return []
