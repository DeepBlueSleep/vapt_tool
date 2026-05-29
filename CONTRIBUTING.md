# Contributing

## Repository Layout

- `scanner/`: Python scanner engine.
- `platform/`: Python API, persistence, reports, and operational web UI.
- `platform/web/`: Cloudflare Pages/Workers app backed exclusively by NeonDB.
- `docs/cloudflare-neon.md`: Deployment guide for Cloudflare and Neon.

## Local Checks

Python tests:

```bash
python -m pytest
```

Cloudflare web app:

```bash
cd platform/web
npm install
npm run check
```

## Secrets

Do not commit secrets. Local Cloudflare variables belong in `platform/web/.dev.vars`, which is ignored.

Required Cloudflare/Neon values:

- `DATABASE_URL_DEV`
- `DATABASE_URL_PROD`
- `JWT_SECRET`

Required GitHub repository secrets for deployment:

- `CLOUDFLARE_API_TOKEN`
- `CLOUDFLARE_ACCOUNT_ID`

## Database Policy

The Cloudflare Workers app must use NeonDB exclusively. Do not add D1, SQLite, local browser storage persistence, or internal platform database dependencies to `platform/web`.

All frontend data access must go through the central wrapper in `platform/web/src/api.ts`, which injects the JWT and `x-assessment-env` header.

