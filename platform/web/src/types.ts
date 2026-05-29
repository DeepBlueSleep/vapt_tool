export type ScanStatus = "queued" | "running" | "completed" | "failed" | "cancelled";

export type Finding = {
  id: number;
  scan_id: number;
  title: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  classification: string;
  confidence: string;
  state: string;
  url: string;
  evidence_summary: string;
  remediation: string;
  risk_score: number;
  occurrence_count: number;
  affected_resources: string[];
};

export type ReportArtifact = {
  id: number;
  scan_id: number;
  audience: "external" | "internal" | string;
  format: "html" | "markdown" | "pdf" | string;
  title: string;
  storage_path?: string | null;
  created_at?: string;
};

export type Evidence = {
  id: number;
  scan_id: number;
  finding_id?: number | null;
  kind: string;
  title: string;
  content_type: string;
  storage_path?: string | null;
  summary: string;
};

export type Scan = {
  id: number;
  target_url: string;
  status: ScanStatus;
  owner?: string | null;
  created_at: string;
  started_at?: string | null;
  completed_at?: string | null;
  posture_score: number;
  posture_grade: string;
  pages_crawled: number;
  error?: string | null;
  inventory: Record<string, string[]>;
  findings: Finding[];
  evidence: Evidence[];
  reports: ReportArtifact[];
};

export type Metrics = {
  scans: number;
  open_findings: number;
  by_severity: Record<string, number>;
  dashboard: {
    posture_timeline: { scan_id: number; target_url: string; score: number; grade: string }[];
    attack_surface_growth: { scan_id: number; runtime_apis: number; endpoints: number; routes: number }[];
  };
};

export type CreateScanRequest = {
  url: string;
  owner?: string;
  max_depth: number;
  max_pages: number;
  request_budget: number;
  enable_browser: boolean;
  enable_active_checks: boolean;
  capture_screenshots: boolean;
  enable_attack_surface_expansion: boolean;
  enable_framework_expansion: boolean;
  enable_predictable_locations: boolean;
  enable_api_expansion: boolean;
  enable_runtime_expansion: boolean;
};

export type AuthUser = {
  id: number;
  email: string;
};

export type AuthResponse = {
  user: AuthUser;
  token: string;
};
