# Runtime Assessment Platform

A Cloudflare Workers application for runtime-aware web security assessment tracking. The frontend is Vite + React + Tailwind, static assets are served by Workers assets, and the API runs in the same Worker with NeonDB Postgres persistence.

## Features

- Scan launcher with runtime and active-check options.
- NeonDB-backed scan, finding, evidence, report, inventory, user, and metrics API.
- Custom Worker auth using a Neon `users` table, PBKDF2-SHA-256 password hashes, and client-side JWT storage.
- POST-only action routing through `/api/auth` and `/api/actions`.
- Responsive dashboard for posture, severity, attack surface, findings, and report artifacts.
- Optional forwarding to a separately hosted Python scanner API through `SCANNER_API_URL`.
- Repo-ready scripts for local development, Neon schema initialization, type checking, build, and Cloudflare Workers deployment.

## Project Layout

```text
src/                 React app
src/components/      Dashboard, auth, scan launcher, lists, reports, UI primitives
src/hooks/           Data loading and polling hooks
worker/              NeonDB-backed Worker API implementation
functions/api/       Legacy Pages Function bridge for compatibility
worker/schema.sql    Neon Postgres schema
wrangler.toml        Cloudflare Workers config
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

Authenticate Wrangler and set required Worker secrets:

```bash
wrangler login
wrangler secret put DATABASE_URL_DEV
wrangler secret put DATABASE_URL_PROD
wrangler secret put JWT_SECRET
```

Deploy:

```bash
npm run deploy
```

Optionally set `SCANNER_API_URL` in `wrangler.toml` or as a Worker secret if it should not be committed.

## GitHub Deployment

This repository includes `.github/workflows/cloudflare-workers.yml`. Add these repository secrets:

```text
CLOUDFLARE_API_TOKEN
CLOUDFLARE_ACCOUNT_ID
```

Before the first GitHub deploy, set the required Worker secrets in Cloudflare:

```text
DATABASE_URL_DEV
DATABASE_URL_PROD
JWT_SECRET
```

Pushes to `main` run `npm run check` from `platform/web` and deploy the Worker with its `dist` static assets.

## Scripts

- `npm run dev`: Vite dev server.
- `npm run build`: TypeScript build and Vite production build.
- `npm run worker:dev`: Build and serve the Worker app locally.
- `npm run worker:serve`: Serve an already-built `dist`.
- `npm run db:init:dev`: Apply the Postgres schema to the Neon development database.
- `npm run db:init:prod`: Apply the Postgres schema to the Neon production database.
- `npm run deploy`: Build and deploy to Cloudflare Workers.
- `npm run check`: Typecheck and build.
