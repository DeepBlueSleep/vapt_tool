# Runtime Assessment Platform

A Cloudflare Pages application for runtime-aware web security assessment tracking. The frontend is Vite + React + Tailwind, and the API runs on the Cloudflare Workers runtime through Pages Functions with NeonDB Postgres persistence.

## Features

- Scan launcher with runtime and active-check options.
- NeonDB-backed scan, finding, evidence, report, inventory, user, and metrics API.
- Custom Worker auth using a Neon `users` table, PBKDF2-SHA-256 password hashes, and client-side JWT storage.
- POST-only action routing through `/api/auth` and `/api/actions`.
- Responsive dashboard for posture, severity, attack surface, findings, and report artifacts.
- Optional forwarding to a separately hosted Python scanner API through `SCANNER_API_URL`.
- Repo-ready scripts for local development, Neon schema initialization, type checking, build, and Cloudflare Pages deployment.

## Project Layout

```text
src/                 React app
src/components/      Dashboard, auth, scan launcher, lists, reports, UI primitives
src/hooks/           Data loading and polling hooks
worker/              NeonDB-backed API implementation
functions/api/       Cloudflare Pages Function bridge into the worker
worker/schema.sql    Neon Postgres schema
wrangler.toml        Cloudflare Pages config
```

## Required Secrets

Set these before running or deploying:

```text
DATABASE_URL_DEV
DATABASE_URL_PROD
JWT_SECRET
```

`DATABASE_URL_DEV` and `DATABASE_URL_PROD` should point to separate Neon branches or projects. The frontend sends `x-assessment-env: dev|prod`; the Worker database factory selects the corresponding Neon connection string.

The database URL is never sent by the browser. The browser sends only the environment flag.

## Local Development

Install dependencies:

```bash
npm install
```

Create local Wrangler variables:

```bash
cp .dev.vars.example .dev.vars
```

Initialize the Neon schemas from a trusted local shell:

```bash
DATABASE_URL_DEV="postgresql://..." npm run db:init:dev
DATABASE_URL_PROD="postgresql://..." npm run db:init:prod
```

Run the full Cloudflare app locally:

```bash
npm run worker:dev
```

Open `http://127.0.0.1:8788`.

For frontend-only iteration, run Vite. API requests proxy to the worker if `worker:serve` is running on port `8788`.

```bash
npm run dev
```

## Scanner Execution

Cloudflare Workers cannot run the Python scanner engine directly. The edge app always stores scan metadata in NeonDB. When `SCANNER_API_URL` is configured, scan creation is forwarded to a separately deployed scanner API.

Without `SCANNER_API_URL`, scans are created in NeonDB with a queued status and an operational note.

## Cloudflare Setup

Create a Pages project:

```bash
wrangler pages project create runtime-assessment-platform
```

Set required Cloudflare Pages secrets:

```bash
wrangler pages secret put DATABASE_URL_DEV --project-name runtime-assessment-platform
wrangler pages secret put DATABASE_URL_PROD --project-name runtime-assessment-platform
wrangler pages secret put JWT_SECRET --project-name runtime-assessment-platform
```

Deploy:

```bash
npm run deploy
```

Optionally add `SCANNER_API_URL` as a Pages environment variable.

## GitHub Deployment

This repository includes `.github/workflows/cloudflare-pages.yml`. Add these repository secrets:

```text
CLOUDFLARE_API_TOKEN
CLOUDFLARE_ACCOUNT_ID
```

Also add the required Cloudflare Pages environment secrets before first deploy:

```text
DATABASE_URL_DEV
DATABASE_URL_PROD
JWT_SECRET
```

Pushes to `main` run `npm run check` and deploy `dist` to Cloudflare Pages.

## Scripts

- `npm run dev`: Vite dev server.
- `npm run build`: TypeScript build and Vite production build.
- `npm run worker:dev`: Build and serve the Pages app locally.
- `npm run worker:serve`: Serve an already-built `dist`.
- `npm run db:init:dev`: Apply the Postgres schema to the Neon development database.
- `npm run db:init:prod`: Apply the Postgres schema to the Neon production database.
- `npm run deploy`: Build and deploy to Cloudflare Pages.
- `npm run check`: Typecheck and build.
