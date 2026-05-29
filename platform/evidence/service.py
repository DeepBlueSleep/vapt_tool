from __future__ import annotations

import json
import zipfile
from pathlib import Path
from platform.database.models import Scan


class EvidenceBundleService:
    def create_bundle(self, scan: Scan, output_path: Path) -> Path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        manifest = {
            "scan_id": scan.id,
            "target_url": scan.target_url,
            "evidence": [
                {
                    "id": item.id,
                    "kind": item.kind,
                    "title": item.title,
                    "storage_path": item.storage_path,
                    "summary": item.summary,
                }
                for item in scan.evidence
            ],
        }
        with zipfile.ZipFile(output_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("manifest.json", json.dumps(manifest, indent=2))
            for item in scan.evidence:
                if not item.storage_path:
                    continue
                path = Path(item.storage_path)
                if path.exists() and path.is_file():
                    archive.write(path, f"evidence/{item.id}-{path.name}")
        return output_path
