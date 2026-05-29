import type { AuthResponse, CreateScanRequest, Metrics, Scan } from "./types";

export type RuntimeEnvironment = "dev" | "prod";

const TOKEN_KEY = "assessment.auth.token";
const ENVIRONMENT_KEY = "assessment.environment";

function currentEnvironment(): RuntimeEnvironment {
  return localStorage.getItem(ENVIRONMENT_KEY) === "prod" ? "prod" : "dev";
}

export function setRuntimeEnvironment(environment: RuntimeEnvironment) {
  localStorage.setItem(ENVIRONMENT_KEY, environment);
}

export function getRuntimeEnvironment(): RuntimeEnvironment {
  return currentEnvironment();
}

export function getStoredToken(): string | null {
  return localStorage.getItem(TOKEN_KEY);
}

export function storeToken(token: string) {
  localStorage.setItem(TOKEN_KEY, token);
}

export function clearToken() {
  localStorage.removeItem(TOKEN_KEY);
}

async function postAction<T>(path: "/api/auth" | "/api/actions", action: string, payload?: Record<string, unknown>): Promise<T> {
  const token = getStoredToken();
  const response = await fetch(path, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-assessment-env": currentEnvironment(),
      ...(token ? { authorization: `Bearer ${token}` } : {})
    },
    body: JSON.stringify({ action, payload: payload ?? {} })
  });
  if (!response.ok) {
    const message = await response.text();
    throw new Error(message || `Request failed with HTTP ${response.status}`);
  }
  if (response.status === 204) {
    return undefined as T;
  }
  return (await response.json()) as T;
}

export const api = {
  login: (email: string, password: string) => postAction<AuthResponse>("/api/auth", "login", { email, password }),
  register: (email: string, password: string) => postAction<AuthResponse>("/api/auth", "register", { email, password }),
  me: () => postAction<{ user: AuthResponse["user"] }>("/api/auth", "me"),
  scans: () => postAction<Scan[]>("/api/actions", "listScans"),
  metrics: () => postAction<Metrics>("/api/actions", "metrics"),
  createScan: (payload: CreateScanRequest) => postAction<{ id: number; status: string; websocket_url?: string }>("/api/actions", "createScan", payload),
  deleteScan: (scanId: number) => postAction<void>("/api/actions", "deleteScan", { scanId }),
  deleteAllScans: () => postAction<void>("/api/actions", "deleteAllScans")
};
