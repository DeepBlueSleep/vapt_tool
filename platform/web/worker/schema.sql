CREATE TABLE IF NOT EXISTS users (
  id BIGSERIAL PRIMARY KEY,
  email TEXT NOT NULL UNIQUE,
  password_salt TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS scans (
  id BIGSERIAL PRIMARY KEY,
  target_url TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'queued',
  owner TEXT REFERENCES users(email) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  started_at TIMESTAMPTZ,
  completed_at TIMESTAMPTZ,
  posture_score DOUBLE PRECISION NOT NULL DEFAULT 0,
  posture_grade TEXT NOT NULL DEFAULT 'n/a',
  pages_crawled INTEGER NOT NULL DEFAULT 0,
  error TEXT,
  inventory_json JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE TABLE IF NOT EXISTS findings (
  id BIGSERIAL PRIMARY KEY,
  scan_id BIGINT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  title TEXT NOT NULL,
  severity TEXT NOT NULL,
  classification TEXT NOT NULL,
  confidence TEXT NOT NULL,
  state TEXT NOT NULL DEFAULT 'new',
  url TEXT NOT NULL,
  evidence_summary TEXT NOT NULL,
  remediation TEXT NOT NULL,
  risk_score DOUBLE PRECISION NOT NULL DEFAULT 0,
  occurrence_count INTEGER NOT NULL DEFAULT 1,
  affected_resources_json JSONB NOT NULL DEFAULT '[]'::jsonb
);

CREATE TABLE IF NOT EXISTS evidence (
  id BIGSERIAL PRIMARY KEY,
  scan_id BIGINT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  finding_id BIGINT REFERENCES findings(id) ON DELETE SET NULL,
  kind TEXT NOT NULL,
  title TEXT NOT NULL,
  content_type TEXT NOT NULL DEFAULT 'text/plain',
  storage_path TEXT,
  summary TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS report_artifacts (
  id BIGSERIAL PRIMARY KEY,
  scan_id BIGINT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  audience TEXT NOT NULL,
  format TEXT NOT NULL,
  title TEXT NOT NULL,
  storage_path TEXT,
  body TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_scans_created ON scans(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_scans_owner ON scans(owner);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_reports_scan ON report_artifacts(scan_id);
