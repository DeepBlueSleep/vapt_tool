import { createJwt, loginUser, registerUser, requireUser, type AuthEnv } from "./auth";
import { databaseForEnvironment, environmentFromRequest, type DatabaseEnv } from "./db";
import type { CreateScanRequest, Evidence, Finding, Metrics, ReportArtifact, Scan } from "../src/types";

export interface Env extends DatabaseEnv, AuthEnv {
  SCANNER_API_URL?: string;
}

type ActionRequest = {
  action: string;
  payload?: Record<string, unknown>;
};

type ErrorPayload = {
  error: string;
  code: string;
  detail?: string;
  hint?: string;
};

type ScanRow = {
  id: number;
  target_url: string;
  status: Scan["status"];
  owner: string | null;
  created_at: string | Date;
  started_at: string | Date | null;
  completed_at: string | Date | null;
  posture_score: number | string;
  posture_grade: string;
  pages_crawled: number;
  error: string | null;
  inventory_json: Record<string, string[]> | string | null;
};

type FindingRow = Omit<Finding, "affected_resources"> & {
  affected_resources_json: string[] | string | null;
};

type EvidenceRow = Evidence;
type ReportRow = ReportArtifact & { body?: string | null };

const jsonHeaders = {
  "content-type": "application/json; charset=utf-8",
  "cache-control": "no-store"
};

const corsHeaders = {
  "access-control-allow-origin": "*",
  "access-control-allow-methods": "POST, OPTIONS",
  "access-control-allow-headers": "content-type, authorization, x-assessment-env",
  "access-control-max-age": "86400"
};

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: corsHeaders });
    const url = new URL(request.url);
    if (!url.pathname.startsWith("/api/")) return new Response("Not found", { status: 404 });
    if (request.method !== "POST") return json({ error: "POST required" }, 405);

    try {
      if (url.pathname === "/api/auth") return await authRoute(request, env);
      if (url.pathname === "/api/actions") {
        const user = await requireUser(request, env);
        return await actionRoute(request, env, ctx, user.email);
      }
      return json({ error: "route not found" }, 404);
    } catch (exc) {
      if (exc instanceof Response) return withCors(exc);
      const error = describeError(request, exc);
      console.error(error.code, error.detail ?? error.error);
      return json(error, error.code === "invalid_credentials" ? 401 : error.code === "bad_request" ? 400 : 500);
    }
  }
};

async function authRoute(request: Request, env: Env): Promise<Response> {
  const body = await readActionRequest(request);
  const appEnv = environmentFromRequest(request);
  const sql = databaseForEnvironment(env, appEnv);
  if (body.action === "register") {
    const user = await registerUser(sql, String(body.payload?.email ?? ""), String(body.payload?.password ?? ""));
    return json({ user, token: await createJwt(env, user) });
  }
  if (body.action === "login") {
    const user = await loginUser(sql, String(body.payload?.email ?? ""), String(body.payload?.password ?? ""));
    return json({ user, token: await createJwt(env, user) });
  }
  if (body.action === "me") {
    const user = await requireUser(request, env);
    return json({ user });
  }
  return json({ error: "unknown auth action" }, 400);
}

async function actionRoute(request: Request, env: Env, ctx: ExecutionContext, owner: string): Promise<Response> {
  const body = await readActionRequest(request);
  switch (body.action) {
    case "listScans":
      return json(await listScans(request, env));
    case "getScan":
      return json(await getScan(request, env, Number(body.payload?.scanId)));
    case "createScan":
      return createScan(request, env, ctx, body.payload as unknown as CreateScanRequest, owner);
    case "deleteScan":
      await deleteScan(request, env, Number(body.payload?.scanId));
      return json({ ok: true });
    case "deleteAllScans":
      await deleteAllScans(request, env);
      return json({ ok: true });
    case "metrics":
      return json(await metrics(request, env));
    case "getReport":
      return reportRoute(request, env, Number(body.payload?.reportId));
    default:
      return json({ error: "unknown action" }, 400);
  }
}

async function readActionRequest(request: Request): Promise<ActionRequest> {
  try {
    const body = (await request.json()) as Partial<ActionRequest>;
    if (!body.action || typeof body.action !== "string") {
      throw new Error("Request JSON must include an action string.");
    }
    return { action: body.action, payload: body.payload };
  } catch (exc) {
    const message = exc instanceof Error ? exc.message : "Invalid request body.";
    throw new AppError("bad_request", "The request body is not valid JSON for this API action.", message, "Retry the request with JSON like { \"action\": \"login\", \"payload\": { ... } }.");
  }
}

async function reportRoute(request: Request, env: Env, reportId: number): Promise<Response> {
  if (!Number.isInteger(reportId)) return json({ error: "invalid report id" }, 400);
  const sql = databaseForEnvironment(env, environmentFromRequest(request));
  const rows = await sql`SELECT * FROM report_artifacts WHERE id = ${reportId} LIMIT 1`;
  const row = rows[0] as ReportRow | undefined;
  if (!row) return json({ error: "report not found" }, 404);
  const mediaType = row.format === "html" ? "text/html; charset=utf-8" : row.format === "markdown" ? "text/markdown; charset=utf-8" : "application/json";
  return withCors(
    new Response(row.body ?? "", {
      headers: {
        "content-type": mediaType,
        "cache-control": "no-store"
      }
    })
  );
}

async function createScan(request: Request, env: Env, ctx: ExecutionContext, payload: CreateScanRequest, owner: string): Promise<Response> {
  if (!payload.url || !/^https?:\/\//i.test(payload.url)) {
    return json({ error: "url must be an absolute http(s) URL" }, 400);
  }
  const sql = databaseForEnvironment(env, environmentFromRequest(request));
  const rows = await sql`
    INSERT INTO scans (target_url, status, owner, inventory_json)
    VALUES (${payload.url}, 'queued', ${owner}, '{}'::jsonb)
    RETURNING id
  `;
  const scanId = Number((rows[0] as { id: number }).id);
  ctx.waitUntil(runScannerIfConfigured(request, env, scanId, payload));
  return json({ id: scanId, status: "queued" }, 201);
}

async function runScannerIfConfigured(request: Request, env: Env, scanId: number, payload: CreateScanRequest): Promise<void> {
  const sql = databaseForEnvironment(env, environmentFromRequest(request));
  if (!env.SCANNER_API_URL) {
    await sql`
      UPDATE scans
      SET status = 'queued', error = ${"No SCANNER_API_URL binding is configured; scan metadata was created but execution was not started."}
      WHERE id = ${scanId}
    `;
    return;
  }
  await sql`UPDATE scans SET status = 'running', started_at = NOW() WHERE id = ${scanId}`;
  try {
    const response = await fetch(new URL("/scans", env.SCANNER_API_URL).toString(), {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(payload)
    });
    if (!response.ok) throw new Error(await response.text());
    await sql`UPDATE scans SET status = 'running' WHERE id = ${scanId}`;
  } catch (exc) {
    const message = exc instanceof Error ? exc.message : "scanner proxy failed";
    await sql`
      UPDATE scans
      SET status = 'failed', completed_at = NOW(), error = ${message.slice(0, 2000)}
      WHERE id = ${scanId}
    `;
  }
}

async function deleteScan(request: Request, env: Env, scanId: number): Promise<void> {
  if (!Number.isInteger(scanId)) throw new Error("invalid scan id");
  const sql = databaseForEnvironment(env, environmentFromRequest(request));
  await sql`DELETE FROM scans WHERE id = ${scanId}`;
}

async function deleteAllScans(request: Request, env: Env): Promise<void> {
  const sql = databaseForEnvironment(env, environmentFromRequest(request));
  await sql`DELETE FROM scans`;
}

async function listScans(request: Request, env: Env): Promise<Scan[]> {
  const sql = databaseForEnvironment(env, environmentFromRequest(request));
  const rows = (await sql`SELECT * FROM scans ORDER BY created_at DESC LIMIT 100`) as ScanRow[];
  return Promise.all(rows.map((row) => hydrateScan(request, env, row)));
}

async function getScan(request: Request, env: Env, scanId: number): Promise<Scan | null> {
  if (!Number.isInteger(scanId)) return null;
  const sql = databaseForEnvironment(env, environmentFromRequest(request));
  const rows = (await sql`SELECT * FROM scans WHERE id = ${scanId} LIMIT 1`) as ScanRow[];
  return rows[0] ? hydrateScan(request, env, rows[0]) : null;
}

async function hydrateScan(request: Request, env: Env, row: ScanRow): Promise<Scan> {
  const sql = databaseForEnvironment(env, environmentFromRequest(request));
  const [findings, evidence, reports] = await Promise.all([
    sql`SELECT * FROM findings WHERE scan_id = ${row.id} ORDER BY risk_score DESC`,
    sql`SELECT * FROM evidence WHERE scan_id = ${row.id} ORDER BY id DESC`,
    sql`
      SELECT id, scan_id, audience, format, title, storage_path, created_at
      FROM report_artifacts
      WHERE scan_id = ${row.id}
      ORDER BY created_at DESC
    `
  ]);
  return {
    id: row.id,
    target_url: row.target_url,
    status: row.status,
    owner: row.owner,
    created_at: asIso(row.created_at),
    started_at: row.started_at ? asIso(row.started_at) : null,
    completed_at: row.completed_at ? asIso(row.completed_at) : null,
    posture_score: Number(row.posture_score),
    posture_grade: row.posture_grade,
    pages_crawled: row.pages_crawled,
    error: row.error,
    inventory: parseJson<Record<string, string[]>>(row.inventory_json, {}),
    findings: (findings as FindingRow[]).map((finding) => ({
      ...finding,
      risk_score: Number(finding.risk_score),
      affected_resources: parseJson<string[]>(finding.affected_resources_json, [])
    })),
    evidence: evidence as EvidenceRow[],
    reports: (reports as ReportArtifact[]).map((report) => ({ ...report, created_at: report.created_at ? asIso(report.created_at) : undefined }))
  };
}

async function metrics(request: Request, env: Env): Promise<Metrics> {
  const scans = await listScans(request, env);
  const bySeverity: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  let openFindings = 0;
  for (const scan of scans) {
    for (const finding of scan.findings) {
      bySeverity[finding.severity] = (bySeverity[finding.severity] ?? 0) + 1;
      if (finding.state !== "resolved" && finding.state !== "suppressed") openFindings += 1;
    }
  }
  return {
    scans: scans.length,
    open_findings: openFindings,
    by_severity: bySeverity,
    dashboard: {
      posture_timeline: scans.map((scan) => ({
        scan_id: scan.id,
        target_url: scan.target_url,
        score: scan.posture_score,
        grade: scan.posture_grade
      })),
      attack_surface_growth: scans.map((scan) => ({
        scan_id: scan.id,
        runtime_apis: scan.inventory.runtime_apis?.length ?? 0,
        endpoints: scan.inventory.endpoints?.length ?? 0,
        routes: (scan.inventory.browser_routes?.length ?? 0) + (scan.inventory.pages?.length ?? 0)
      }))
    }
  };
}

function parseJson<T>(value: unknown, fallback: T): T {
  if (!value) return fallback;
  if (typeof value !== "string") return value as T;
  try {
    return JSON.parse(value) as T;
  } catch {
    return fallback;
  }
}

function asIso(value: string | Date): string {
  return value instanceof Date ? value.toISOString() : value;
}

function json(payload: unknown, status = 200): Response {
  return withCors(
    new Response(JSON.stringify(payload), {
      status,
      headers: jsonHeaders
    })
  );
}

function withCors(response: Response): Response {
  const headers = new Headers(response.headers);
  for (const [key, value] of Object.entries(corsHeaders)) headers.set(key, value);
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
}

class AppError extends Error {
  constructor(
    public code: string,
    message: string,
    public detail?: string,
    public hint?: string
  ) {
    super(message);
  }
}

function describeError(request: Request, exc: unknown): ErrorPayload {
  const appEnv = environmentFromRequest(request);
  const message = exc instanceof Error ? exc.message : String(exc);
  const normalized = message.toLowerCase();

  if (exc instanceof AppError) {
    return { error: exc.message, code: exc.code, detail: exc.detail, hint: exc.hint };
  }
  if (/invalid email or password|account already exists|password must|valid email|token expired|invalid token|authentication required/i.test(message)) {
    return { error: message, code: "invalid_credentials" };
  }
  if (normalized.includes("jwt_secret")) {
    return {
      error: "JWT signing is not configured on this Worker.",
      code: "jwt_secret_missing",
      detail: "JWT_SECRET is missing or empty.",
      hint: "Set JWT_SECRET with wrangler secret put JWT_SECRET."
    };
  }
  if (normalized.includes(`database_url_${appEnv.toUpperCase().toLowerCase()}`) || normalized.includes("is not configured")) {
    return {
      error: `The ${appEnv.toUpperCase()} database secret is not configured on this Worker.`,
      code: "database_secret_missing",
      detail: `DATABASE_URL_${appEnv.toUpperCase()} is missing or empty.`,
      hint: `Set DATABASE_URL_${appEnv.toUpperCase()} with wrangler secret put, then redeploy or retry after the secret is active.`
    };
  }
  if (normalized.includes('relation "users" does not exist') || normalized.includes("schema") || normalized.includes("does not exist")) {
    return {
      error: `The ${appEnv.toUpperCase()} database schema has not been initialized.`,
      code: "database_schema_missing",
      detail: message,
      hint: `Run the SQL in worker/schema.sql against the same database configured as DATABASE_URL_${appEnv.toUpperCase()}, then insert or register a user.`
    };
  }
  if (normalized.includes("password authentication failed") || normalized.includes("role") || normalized.includes("permission denied")) {
    return {
      error: `The ${appEnv.toUpperCase()} database credentials are not valid for this Neon database.`,
      code: "database_credentials_invalid",
      detail: message,
      hint: `Check that DATABASE_URL_${appEnv.toUpperCase()} is copied exactly from Neon and points to the intended branch/database.`
    };
  }
  if (normalized.includes("fetch failed") || normalized.includes("network") || normalized.includes("timeout") || normalized.includes("connect")) {
    return {
      error: `The Worker could not connect to the ${appEnv.toUpperCase()} Neon database.`,
      code: "database_connection_failed",
      detail: message,
      hint: `Check the DATABASE_URL_${appEnv.toUpperCase()} host, Neon project status, and whether the URL includes sslmode=require.`
    };
  }

  return {
    error: "The Worker hit an unexpected server error.",
    code: "unexpected_server_error",
    detail: message,
    hint: "Check the Worker logs for this request and verify the selected environment database secret and schema."
  };
}
