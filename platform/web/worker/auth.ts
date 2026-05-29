import type { NeonQueryFunction } from "@neondatabase/serverless";

export type AuthUser = {
  id: number;
  email: string;
};

export interface AuthEnv {
  JWT_SECRET?: string;
}

const encoder = new TextEncoder();

export async function registerUser(sql: NeonQueryFunction<false, false>, email: string, password: string): Promise<AuthUser> {
  assertCredentials(email, password);
  const salt = randomToken(16);
  const passwordHash = await hashPassword(password, salt);
  try {
    const rows = await sql`
      INSERT INTO users (email, password_salt, password_hash)
      VALUES (${email.toLowerCase()}, ${salt}, ${passwordHash})
      RETURNING id, email
    `;
    return rows[0] as AuthUser;
  } catch (exc) {
    const message = exc instanceof Error ? exc.message : "";
    if (message.includes("duplicate") || message.includes("unique")) {
      throw new Error("An account already exists for this email.");
    }
    throw exc;
  }
}

export async function loginUser(sql: NeonQueryFunction<false, false>, email: string, password: string): Promise<AuthUser> {
  const rows = await sql`SELECT id, email, password_salt, password_hash FROM users WHERE email = ${email.toLowerCase()} LIMIT 1`;
  const user = rows[0] as (AuthUser & { password_salt: string; password_hash: string }) | undefined;
  if (!user) throw new Error("Invalid email or password.");
  const candidate = await hashPassword(password, user.password_salt);
  if (!timingSafeEqual(candidate, user.password_hash)) {
    throw new Error("Invalid email or password.");
  }
  return { id: user.id, email: user.email };
}

export async function createJwt(env: AuthEnv, user: AuthUser): Promise<string> {
  const header = base64UrlJson({ alg: "HS256", typ: "JWT" });
  const now = Math.floor(Date.now() / 1000);
  const payload = base64UrlJson({
    sub: String(user.id),
    email: user.email,
    iat: now,
    exp: now + 60 * 60 * 24 * 7
  });
  const signature = await sign(`${header}.${payload}`, jwtSecret(env));
  return `${header}.${payload}.${signature}`;
}

export async function requireUser(request: Request, env: AuthEnv): Promise<AuthUser> {
  const authorization = request.headers.get("authorization") ?? "";
  const token = authorization.startsWith("Bearer ") ? authorization.slice("Bearer ".length) : "";
  if (!token) throw new Response(JSON.stringify({ error: "authentication required" }), { status: 401 });
  return verifyJwt(env, token);
}

export async function verifyJwt(env: AuthEnv, token: string): Promise<AuthUser> {
  const [header, payload, signature] = token.split(".");
  if (!header || !payload || !signature) throw new Error("Invalid token.");
  const expected = await sign(`${header}.${payload}`, jwtSecret(env));
  if (!timingSafeEqual(signature, expected)) throw new Error("Invalid token.");
  const claims = JSON.parse(new TextDecoder().decode(base64UrlDecode(payload))) as { sub?: string; email?: string; exp?: number };
  if (!claims.sub || !claims.email || !claims.exp || claims.exp < Math.floor(Date.now() / 1000)) {
    throw new Error("Token expired.");
  }
  return { id: Number(claims.sub), email: claims.email };
}

async function hashPassword(password: string, salt: string): Promise<string> {
  const key = await crypto.subtle.importKey("raw", encoder.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      hash: "SHA-256",
      salt: encoder.encode(salt),
      iterations: 210_000
    },
    key,
    256
  );
  return base64Url(new Uint8Array(bits));
}

async function sign(value: string, secret: string): Promise<string> {
  const key = await crypto.subtle.importKey("raw", encoder.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const signature = await crypto.subtle.sign("HMAC", key, encoder.encode(value));
  return base64Url(new Uint8Array(signature));
}

function jwtSecret(env: AuthEnv): string {
  if (!env.JWT_SECRET) throw new Error("JWT_SECRET is not configured");
  return env.JWT_SECRET;
}

function assertCredentials(email: string, password: string): void {
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) throw new Error("Enter a valid email address.");
  if (password.length < 10) throw new Error("Password must be at least 10 characters.");
}

function randomToken(bytes: number): string {
  const buffer = new Uint8Array(bytes);
  crypto.getRandomValues(buffer);
  return base64Url(buffer);
}

function base64UrlJson(value: unknown): string {
  return base64Url(encoder.encode(JSON.stringify(value)));
}

function base64Url(value: Uint8Array): string {
  let binary = "";
  value.forEach((byte) => {
    binary += String.fromCharCode(byte);
  });
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function base64UrlDecode(value: string): Uint8Array {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(value.length / 4) * 4, "=");
  const binary = atob(normalized);
  return Uint8Array.from(binary, (char) => char.charCodeAt(0));
}

function timingSafeEqual(first: string, second: string): boolean {
  if (first.length !== second.length) return false;
  let diff = 0;
  for (let index = 0; index < first.length; index += 1) {
    diff |= first.charCodeAt(index) ^ second.charCodeAt(index);
  }
  return diff === 0;
}

