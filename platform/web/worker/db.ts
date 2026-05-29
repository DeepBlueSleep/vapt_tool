import { neon, type NeonQueryFunction } from "@neondatabase/serverless";

export type AppEnvironment = "dev" | "prod";

export interface DatabaseEnv {
  DATABASE_URL_DEV?: string;
  DATABASE_URL_PROD?: string;
}

const ENVIRONMENT_HEADER = "x-assessment-env";
const clients = new Map<AppEnvironment, NeonQueryFunction<false, false>>();

export function environmentFromRequest(request: Request): AppEnvironment {
  const value = request.headers.get(ENVIRONMENT_HEADER)?.toLowerCase();
  return value === "prod" ? "prod" : "dev";
}

export function databaseForEnvironment(env: DatabaseEnv, appEnv: AppEnvironment): NeonQueryFunction<false, false> {
  const url = appEnv === "prod" ? env.DATABASE_URL_PROD : env.DATABASE_URL_DEV;
  if (!url) {
    throw new Error(`DATABASE_URL_${appEnv.toUpperCase()} is not configured`);
  }
  const cached = clients.get(appEnv);
  if (cached) return cached;
  const client = neon(url);
  clients.set(appEnv, client);
  return client;
}

