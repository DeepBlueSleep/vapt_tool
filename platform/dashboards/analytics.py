from __future__ import annotations

from collections import Counter
from platform.database.models import Scan
from typing import Any


def build_dashboard_summary(scans: list[Scan]) -> dict[str, Any]:
    severities: Counter[str] = Counter()
    states: Counter[str] = Counter()
    posture = []
    api_counts = []
    for scan in scans:
        posture.append({"scan_id": scan.id, "target_url": scan.target_url, "score": scan.posture_score, "grade": scan.posture_grade})
        api_counts.append(
            {
                "scan_id": scan.id,
                "runtime_apis": len(scan.inventory.get("runtime_apis", [])),
                "endpoints": len(scan.inventory.get("endpoints", [])),
                "routes": len(scan.inventory.get("browser_routes", [])) + len(scan.inventory.get("pages", [])),
            }
        )
        for finding in getattr(scan, "findings", []):
            severities[finding.severity] += 1
            states[finding.state] += 1
    return {
        "scan_count": len(scans),
        "severity_counts": dict(severities),
        "workflow_counts": dict(states),
        "posture_timeline": posture,
        "attack_surface_growth": api_counts,
    }
