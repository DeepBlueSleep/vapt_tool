"""Opt-in OSV queries for explicit JavaScript library banner versions."""
from __future__ import annotations

import asyncio
import json
import re
from urllib.parse import quote

import aiohttp

from scanner.checks.common import make_finding
from scanner.core.models import Classification, Confidence, Reference, Severity, TargetReport

_BANNER = re.compile(
    r"(?:/\*[!*]?\s*|\n\s*\*\s*)(jQuery|Bootstrap|Lodash|Vue(?:\.js)?|"
    r"React|DOMPurify|Moment(?:\.js)?)\s+v?(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)"
    r"(?=\s|\*/|$)", re.I,
)
_PACKAGES = {"jquery": "jquery", "bootstrap": "bootstrap", "lodash": "lodash",
             "vue": "vue", "vue.js": "vue", "react": "react", "dompurify": "dompurify",
             "moment": "moment", "moment.js": "moment"}


def identify_libraries(content: str) -> set[tuple[str, str]]:
    return {(_PACKAGES[name.lower()], version) for name, version in _BANNER.findall(content)}


class CveEnricher:
    """Per-target cache; bounded requests, no target URLs sent to OSV."""

    def __init__(self, budget: int = 30) -> None:
        self.budget = budget
        self.requests = 0
        self.cache: dict[tuple[str, str], list[dict]] = {}

    async def _query(self, session, payload: dict) -> dict:
        if self.requests >= self.budget:
            raise ValueError("Advisory request limit reached")
        self.requests += 1
        async with session.post("https://api.osv.dev/v1/query", json=payload,
                                allow_redirects=False) as response:
            if response.status != 200:
                raise ValueError(f"OSV returned HTTP {response.status}")
            try:
                raw = await response.content.readexactly(2_000_001)
            except asyncio.IncompleteReadError as exc:
                raw = exc.partial
            if len(raw) > 2_000_000:
                raise ValueError("OSV response exceeded inspection limit")
            data = json.loads(raw)
            if not isinstance(data, dict) or not isinstance(data.get("vulns", []), list):
                raise ValueError("Invalid OSV response")
            return data

    async def lookup(self, session, name: str, version: str) -> list[dict]:
        key = (name, version)
        if key in self.cache:
            return self.cache[key]
        payload = {"package": {"name": name, "ecosystem": "npm"}, "version": version}
        records: dict[str, dict] = {}
        while True:
            data = await self._query(session, payload)
            for record in data.get("vulns", []):
                if not isinstance(record, dict) or not isinstance(record.get("id"), str):
                    raise ValueError("Malformed OSV advisory")
                if not record.get("withdrawn"):
                    records[record["id"]] = record
            token = data.get("next_page_token")
            if not token:
                break
            if not isinstance(token, str):
                raise ValueError("Invalid OSV pagination token")
            payload["page_token"] = token
        self.cache[key] = list(records.values())
        return self.cache[key]


async def enrich_report(report: TargetReport, libraries: dict[tuple[str, str], set[str]]) -> None:
    enricher = CveEnricher()
    report.inventory["dependency_advisories"] = []
    checked = 0
    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=25)) as session:
        for (name, version), resources in sorted(libraries.items()):
            try:
                records = await enricher.lookup(session, name, version)
            except (aiohttp.ClientError, asyncio.TimeoutError, ValueError) as exc:
                report.errors.append(f"Advisory lookup incomplete for {name}@{version}: {exc}")
                continue
            checked += 1
            report.inventory["dependency_advisories"].append(
                f"{name}@{version}: {len(records)} OSV advisories; version inferred from a script banner."
            )
            for record in records:
                advisory = record["id"]
                for url in sorted(resources):
                    report.findings.append(make_finding(
                        check="dependencies.osv", url=url,
                        title=f"Library version has known advisory: {name}@{version} ({advisory})",
                        severity=Severity.MEDIUM, classification=Classification.WEAKNESS,
                        confidence=Confidence.MEDIUM,
                        evidence=f"Explicit script banner identifies {name}@{version}. OSV returned {advisory}. "
                                 "Library identity and application exploitability require verification.",
                        remediation="Confirm the deployed package and affected features, then upgrade to a "
                                    "supported version that resolves the linked advisory.",
                        dedup_key=f"osv:{name}:{version}:{advisory}",
                        references=[Reference(advisory, f"https://osv.dev/vulnerability/{quote(advisory, safe='')}")],
                        metadata={"package": name, "version": version, "advisory_id": advisory,
                                  "aliases": record.get("aliases", []),
                                  "provider_severity": record.get("severity", []),
                                  "exploitability_verified": False},
                    ))
    report.metrics["advisory_requests"] = enricher.requests
    report.metrics["dependency_versions_checked"] = checked
    report.inventory["coverage"].append(
        f"OSV advisory checks: {checked}/{len(libraries)} detected package versions; "
        f"{enricher.requests}/30 separate advisory requests. Banner detection covers selected libraries only."
    )
