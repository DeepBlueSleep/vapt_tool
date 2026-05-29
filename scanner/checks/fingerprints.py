from __future__ import annotations

import re

from scanner.core.models import Finding, Page, TargetReport
from scanner.plugins.base import PluginMetadata


class TechnologyFingerprintCheck:
    metadata = PluginMetadata(
        name="passive.fingerprints",
        version="1.0",
        description="Collects passive server, framework, CMS, CDN, and JavaScript library fingerprints.",
        category="passive",
    )

    async def analyze(self, page: Page, report: TargetReport) -> list[Finding]:
        server = _first(page.headers, "server")
        powered_by = _first(page.headers, "x-powered-by")
        if server:
            report.technologies.setdefault("server", server)
        if powered_by:
            report.technologies.setdefault("powered_by", powered_by)
        text = page.body[:250_000].decode("utf-8", "ignore")
        if "wp-content" in text or "wp-includes" in text:
            report.technologies.setdefault("cms", "WordPress")
        for library, pattern in {
            "jquery": r"jquery[-.]([0-9][^\"'/\s]+)",
            "bootstrap": r"bootstrap(?:\.min)?\.js\?*v?=?([0-9][^\"'/\s]*)",
            "react": r"react(?:\.production)?(?:\.min)?\.js",
            "vue": r"vue(?:\.runtime)?(?:\.min)?\.js",
        }.items():
            match = re.search(pattern, text, re.I)
            if match:
                version = match.group(1) if match.lastindex else "detected"
                report.technologies.setdefault(f"js:{library}", version)
        cdn_markers = ("cloudflare", "akamai", "fastly", "cloudfront")
        headers_text = " ".join(value for values in page.headers.values() for value in values).lower()
        for marker in cdn_markers:
            if marker in headers_text:
                report.technologies.setdefault("cdn_waf", marker)
        report.inventory.setdefault("scripts", [])
        for script in page.scripts:
            if script not in report.inventory["scripts"]:
                report.inventory["scripts"].append(script)
        return []


def _first(headers: dict[str, list[str]], name: str) -> str | None:
    values = headers.get(name.lower())
    return values[0] if values else None
