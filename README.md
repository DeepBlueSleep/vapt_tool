# Safe Website Security Scanner

`website_auditor.py` is now a compatibility wrapper around the `scanner` package: a safe, asynchronous, modular website security assessment framework for authorized defensive testing.

The scanner is intentionally legality-aware and conservative by default:

- Scope is restricted to the input host unless explicitly expanded.
- `robots.txt` is respected by default.
- Requests are rate-limited and concurrency-bounded.
- Active checks are disabled unless `--enable-active-checks` is set.
- Active checks use only low-impact heuristics and benign markers.
- The scanner does not exploit vulnerabilities, fuzz aggressively, bypass authentication, brute force, or perform destructive actions.

## Architecture

```text
scanner/
  core/           config, models, HTTP client, scope, orchestration, enrichment seams
  checks/         passive checks, safe active checks, discovery checks, fingerprinting
  crawlers/       async crawler, robots.txt, sitemap parsing, HTML extraction
  reporting/      JSON, Markdown, and HTML reports with risk scoring
  utils/          URL normalization and structured logging
  fingerprints/  dependency fingerprint data structures
  browser/        optional Playwright-assisted analysis seam
  plugins/        plugin metadata, registry, and example plugin
platform/web/     Cloudflare Pages/Workers app backed exclusively by NeonDB
```

## Current Capabilities

- Async crawling with depth and page limits.
- URL normalization and deduplicated crawl queue.
- Explicit scope enforcement and denylist support.
- `robots.txt` support.
- `sitemap.xml` parsing.
- HTML, form, parameter, asset, and JavaScript file discovery.
- JavaScript-aware endpoint, route, websocket, dynamic import, and framework discovery.
- Comprehensive parameter harvesting from URLs, forms, hidden inputs, JavaScript, REST-style routes, and GraphQL hints.
- API surface discovery for OpenAPI, Swagger, GraphQL, REST, and common platform APIs.
- Passive security header and CSP analysis.
- Cookie flag analysis.
- Basic technology fingerprinting from headers and HTML.
- API and `security.txt` endpoint discovery.
- Common exposed-file checks for a small safe path list.
- Optional low-impact active checks for CORS, advertised HTTP methods, benign reflection, weak cache headers, and open redirects.
- Response diffing and reflection context classification for HTML body, attributes, JavaScript strings, comments, and JSON.
- Finding correlation by global, host, path, endpoint, or parameter scope.
- Aggregated findings with occurrence counts and affected resource samples.
- Event dispatcher for async scanner lifecycle hooks.
- Optional Playwright browser-assisted analysis for SPA routes, console errors, network requests, mixed content, and screenshots.
- Recursive browser-to-crawler feedback: browser-discovered routes and runtime APIs are normalized, filtered, scored, scope-checked, and reprocessed within route/API budgets.
- SPA route instrumentation for History API transitions, hash routing, framework route attributes, and runtime-generated links.
- Runtime API capture for `fetch`, XHR, GraphQL-like calls, websockets, REST APIs, auth-required status hints, and request field metadata.
- DOM mutation observation for dynamically-added links and forms.
- Browser-aware false-positive suppression for analytics, fonts, media, source maps, high-entropy transient paths, and low-value assets.
- Attack surface graph summaries for pages, APIs, forms, scripts, routes, parameters, auth signals, and runtime edges.
- Auth-aware discovery for login forms, auth-like routes, CSRF/token-like fields, and auth-required API statuses. The scanner never attempts credential attacks or auth bypass.
- Runtime API active analysis, when active checks are enabled, using low-impact JSON reflection checks, verbose error/schema leak heuristics, CORS/method checks, and response diffing.
- JSON, Markdown, and HTML reports.
- Finding deduplication and risk scoring.
- Plugin registry with async hooks.

## Usage

```powershell
python .\website_auditor.py https://example.com
```

Scan with a deeper crawl:

```powershell
python .\website_auditor.py https://example.com --max-depth 2 --max-pages 100 --rate-limit 1
```

Opt in to low-impact active checks:

```powershell
python .\website_auditor.py https://example.com --enable-active-checks
```

Enable browser-assisted analysis:

```powershell
python .\website_auditor.py https://example.com --browser --capture-screenshots
```

Enable recursive browser feedback with small budgets:

```powershell
python .\website_auditor.py https://example.com --browser --browser-max-rounds 2 --browser-route-budget 10 --browser-api-budget 10
```

Trace requests and include metrics:

```powershell
python .\website_auditor.py https://example.com --metrics --trace-requests
```

Trace browser feedback:

```powershell
python .\website_auditor.py https://example.com --browser --trace-spa --trace-dom --trace-runtime-api --trace-feedback-loop
```

Generate audience-specific reports:

```powershell
python .\website_auditor.py https://example.com --report-mode executive
python .\website_auditor.py https://example.com --report-mode developer
python .\website_auditor.py https://example.com --report-mode compliance
python .\website_auditor.py https://example.com --report-mode api-focused
python .\website_auditor.py https://example.com --report-mode runtime-focused
```

Export additional integration formats:

```powershell
python .\website_auditor.py https://example.com --export sarif --export csv --export junit
```

Compare against a previous JSON report:

```powershell
python .\website_auditor.py https://example.com --baseline .\audit-reports\website-audit-previous.json
```

Skip exposed-file discovery:

```powershell
python .\website_auditor.py https://example.com --skip-exposure-checks
```

The command writes:

- `website-audit-YYYYMMDD-HHMMSS.json`
- `website-audit-YYYYMMDD-HHMMSS.md`
- `website-audit-YYYYMMDD-HHMMSS.html`

## Development

Install dependencies:

```powershell
python -m pip install -e ".[dev]"
```

Run tests:

```powershell
pytest
```

## Cloudflare Web App

The deployable web app lives in `platform/web`. It is a Vite React dashboard with a Cloudflare Pages Function/Worker API and NeonDB persistence.

```powershell
cd .\platform\web
npm install
copy .dev.vars.example .dev.vars
npm run worker:dev
```

Before running it, set `DATABASE_URL_DEV`, `DATABASE_URL_PROD`, and `JWT_SECRET` in `platform/web/.dev.vars`, then initialize Neon:

```powershell
$env:DATABASE_URL_DEV="postgresql://..."
npm run db:init:dev
$env:DATABASE_URL_PROD="postgresql://..."
npm run db:init:prod
```

Open `http://127.0.0.1:8788`. The Worker stores scan metadata in NeonDB and can forward scan creation to the Python API when `SCANNER_API_URL` is configured.

This repo includes a root GitHub Actions workflow at `.github/workflows/cloudflare-pages.yml` that checks and deploys `platform/web` to Cloudflare Pages on pushes to `main`.

Deployment details are in [docs/cloudflare-neon.md](docs/cloudflare-neon.md).

Required GitHub repository secrets:

- `CLOUDFLARE_API_TOKEN`
- `CLOUDFLARE_ACCOUNT_ID`

Required Cloudflare Pages secrets:

- `DATABASE_URL_DEV`
- `DATABASE_URL_PROD`
- `JWT_SECRET`

Optional browser support:

```powershell
python -m pip install -e ".[browser]"
playwright install chromium
```

## Roadmap

The package includes stable seams for additional production phases:

- CVE, CVSS, and EPSS enrichment workers in `scanner/core/enrichment.py`.
- Plugin package auto-discovery and richer lifecycle controls in `scanner/plugins`.
- Dependency vulnerability mapping in `scanner/fingerprints`.
- Larger integration fixtures and benchmark targets in `benchmarks/`.
- Browser pool reuse can be expanded from the bounded pool abstraction in `scanner/browser/pool.py`.
- PDF, Jira, and DefectDojo exports can build on the structured export package in `scanner/export`.

Only scan websites you own or have explicit permission to assess.
