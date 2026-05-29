# Cloudflare Workers + NeonDB Deployment

This repository's deployable web app is in `platform/web`. It is designed for Cloudflare Pages Functions/Workers and uses NeonDB exclusively for persistence.

## Required Secrets

Create two Neon connection strings, ideally from separate Neon branches or projects:

- `DATABASE_URL_DEV`
- `DATABASE_URL_PROD`

Also create a long random JWT signing secret:

- `JWT_SECRET`

Set them in Cloudflare Pages:

```bash
wrangler pages secret put DATABASE_URL_DEV --project-name runtime-assessment-platform
wrangler pages secret put DATABASE_URL_PROD --project-name runtime-assessment-platform
wrangler pages secret put JWT_SECRET --project-name runtime-assessment-platform
```

Optional scanner forwarding:

```bash
wrangler pages secret put SCANNER_API_URL --project-name runtime-assessment-platform
```

## Initialize Neon Schema

From `platform/web`:

```bash
DATABASE_URL_DEV="postgresql://..." npm run db:init:dev
DATABASE_URL_PROD="postgresql://..." npm run db:init:prod
```

The schema is in `platform/web/worker/schema.sql`.

## Local Development

Create `platform/web/.dev.vars` from the example:

```bash
cp platform/web/.dev.vars.example platform/web/.dev.vars
```

Then run:

```bash
cd platform/web
npm install
npm run worker:dev
```

Open `http://127.0.0.1:8788`.

## Request Flow

The frontend never receives a database URL.

```text
React UI
  -> central API wrapper
  -> POST /api/auth or POST /api/actions
  -> Authorization + x-assessment-env headers
  -> Worker auth/action route
  -> Neon factory selects DATABASE_URL_DEV or DATABASE_URL_PROD
  -> NeonDB
```

The environment selector is the `x-assessment-env` header. Valid values are `dev` and `prod`; missing or invalid values default to `dev`.

## GitHub Actions

The root workflow is `.github/workflows/cloudflare-pages.yml`.

Required GitHub repository secrets:

```text
CLOUDFLARE_API_TOKEN
CLOUDFLARE_ACCOUNT_ID
```

Required Cloudflare Pages secrets:

```text
DATABASE_URL_DEV
DATABASE_URL_PROD
JWT_SECRET
```

Pushes to `main` build and deploy `platform/web/dist`.
