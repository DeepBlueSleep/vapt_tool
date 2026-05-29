from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ScanDiff:
    new_findings: tuple[str, ...]
    fixed_findings: tuple[str, ...]
    unchanged_findings: tuple[str, ...]
    attack_surface_changes: tuple[str, ...]


def compare_report_files(previous_path: Path, current_path: Path) -> ScanDiff:
    previous = json.loads(previous_path.read_text(encoding="utf-8"))
    current = json.loads(current_path.read_text(encoding="utf-8"))
    previous_findings = _finding_keys(previous)
    current_findings = _finding_keys(current)
    previous_surface = _surface_keys(previous)
    current_surface = _surface_keys(current)
    return ScanDiff(
        new_findings=tuple(sorted(current_findings - previous_findings)),
        fixed_findings=tuple(sorted(previous_findings - current_findings)),
        unchanged_findings=tuple(sorted(previous_findings & current_findings)),
        attack_surface_changes=tuple(sorted(current_surface ^ previous_surface)),
    )


def render_diff_markdown(diff: ScanDiff) -> str:
    lines = ["# Scan Delta Report", "", "## New Findings", ""]
    lines.extend(f"- {item}" for item in diff.new_findings or ("None",))
    lines.extend(["", "## Fixed Findings", ""])
    lines.extend(f"- {item}" for item in diff.fixed_findings or ("None",))
    lines.extend(["", "## Attack Surface Drift", ""])
    lines.extend(f"- {item}" for item in diff.attack_surface_changes or ("None",))
    return "\n".join(lines) + "\n"


def _finding_keys(payload: dict[str, object]) -> set[str]:
    keys: set[str] = set()
    targets = payload.get("targets", [])
    if not isinstance(targets, list):
        return keys
    for target in targets:
        if not isinstance(target, dict):
            continue
        for finding in target.get("findings", []):
            if isinstance(finding, dict):
                keys.add(str(finding.get("dedup_key") or finding.get("id") or finding.get("title")))
    return keys


def _surface_keys(payload: dict[str, object]) -> set[str]:
    keys: set[str] = set()
    targets = payload.get("targets", [])
    if not isinstance(targets, list):
        return keys
    for target in targets:
        if not isinstance(target, dict):
            continue
        inventory = target.get("inventory", {})
        if not isinstance(inventory, dict):
            continue
        for name, values in inventory.items():
            if isinstance(values, list):
                keys.update(f"{name}:{value}" for value in values)
    return keys
