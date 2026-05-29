from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class DependencyFingerprint:
    name: str
    version: str | None
    source: str


KNOWN_OUTDATED_FRONTEND = {
    "jquery": {
        "1.12.4": "Known legacy jQuery branch; review for CVE exposure and upgrade to a supported release.",
        "2.2.4": "Known legacy jQuery branch; review for CVE exposure and upgrade to a supported release.",
        "3.4.1": "Older jQuery version; upgrade to a current release after compatibility testing.",
    }
}
