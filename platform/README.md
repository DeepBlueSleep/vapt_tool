# Assessment Platform

This package turns the scanner engine into a runtime-aware assessment platform while keeping `scanner/` independently usable.

## Local API

```bash
pip install -e ".[platform,browser]"
assessment-platform --host 127.0.0.1 --port 8000 --reload
```

From a checkout that has not been reinstalled after adding the console script, run the module directly:

```bash
python -m platform.api --host 127.0.0.1 --port 8000 --reload
```

OpenAPI docs are available at `http://127.0.0.1:8000/docs`.

The operational web UI is served by the same FastAPI process:

- Dashboard and scan launch: `http://127.0.0.1:8000/`
- Live scan progress: `http://127.0.0.1:8000/scan/{scan_id}`
- Results and report workflow: `http://127.0.0.1:8000/reports/{scan_id}`
- Findings explorer: `http://127.0.0.1:8000/findings`
- Evidence viewer: `http://127.0.0.1:8000/evidence/{scan_id}`
- External PDF: `http://127.0.0.1:8000/reports/{scan_id}/external.pdf`
- Internal PDF: `http://127.0.0.1:8000/reports/{scan_id}/internal.pdf`

## Web UI

```bash
cd platform/web
npm install
npm run dev
```

The production web app is a Cloudflare Pages/Workers application. It serves a Vite React dashboard with a NeonDB-backed Worker API under `/api/*`.

```bash
cd platform/web
npm install
npm run build
npm run worker:dev
```

The Worker can optionally proxy scan creation to the Python assessment API when `SCANNER_API_URL` is configured. Without that binding, the edge app still manages scan metadata, reports, evidence records, users, and deletion workflow in NeonDB.

## Docker

```bash
docker compose up --build
```

API: `http://localhost:8000`
Web: `http://localhost:3000`

## CLI Persistence

The scanner remains usable as a CLI and can write into the platform database:

```bash
safe-website-scanner https://example.com --persist --database-url sqlite+aiosqlite:///./platform.db
```

## Architecture

- `scanner/`: independently usable scan engine and legacy report writers
- `platform/api/`: FastAPI endpoints, websocket progress, background scan queue
- `platform/database/`: async SQLAlchemy persistence and migrations
- `platform/reporting/`: external/internal report generation
- `platform/exports/`: PDF rendering
- `platform/evidence/`: evidence bundle management
- `platform/dashboards/`: posture and attack-surface analytics
- `platform/auth/`: initial role model
- `platform/web/`: Cloudflare-ready Vite React dashboard and NeonDB Worker API
