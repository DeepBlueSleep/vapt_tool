import { neon } from "@neondatabase/serverless";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const target = process.argv[2] === "prod" ? "prod" : "dev";
const envName = target === "prod" ? "DATABASE_URL_PROD" : "DATABASE_URL_DEV";
const databaseUrl = process.env[envName];

if (!databaseUrl) {
  throw new Error(`${envName} must be set before initializing Neon schema.`);
}

const schema = readFileSync(resolve("worker/schema.sql"), "utf8");
const statements = schema
  .split(";")
  .map((statement) => statement.trim())
  .filter(Boolean);

const sql = neon(databaseUrl);
for (const statement of statements) {
  await sql.query(statement);
}

console.log(`Initialized Neon ${target} database with ${statements.length} statements.`);
