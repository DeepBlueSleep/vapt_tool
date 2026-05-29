# Security Policy

This project is intended for authorized defensive security assessment only.

## Reporting Issues

Do not open public issues containing live secrets, exploitable target details, private URLs, credentials, or customer data. Share a minimal reproduction with sensitive values redacted.

## Secret Handling

Never commit:

- Neon connection strings
- Cloudflare API tokens
- JWT signing secrets
- Scanner target credentials
- Generated reports containing private findings

Use Cloudflare Pages secrets for production values and `platform/web/.dev.vars` for local development.

## Scanner Safety

The scanner is conservative by default. Active checks are opt-in and should only be used against systems you own or have explicit authorization to assess.

