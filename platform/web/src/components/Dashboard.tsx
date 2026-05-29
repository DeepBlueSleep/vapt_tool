import { Activity, BarChart3, CheckCircle2, ShieldCheck } from "lucide-react";
import { useMemo, useState } from "react";
import { Area, AreaChart, Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";

import type { Metrics, Scan } from "../types";
import { FindingList } from "./FindingList";
import { Inventory } from "./Inventory";
import { ReportList } from "./ReportList";
import { Metric, Panel } from "./ui";

type View = "overview" | "findings" | "surface" | "reports";

const severities = ["critical", "high", "medium", "low", "info"] as const;

export function Dashboard({ activeView, metrics, selected }: { activeView: View; metrics: Metrics | null; selected: Scan | null }) {
  const [query, setQuery] = useState("");
  const [severity, setSeverity] = useState("all");
  const severityData = severities.map((name) => ({ name, value: metrics?.by_severity[name] ?? 0 }));
  const filteredFindings = useMemo(() => {
    return (selected?.findings ?? []).filter((finding) => {
      const text = `${finding.title} ${finding.url} ${finding.evidence_summary}`.toLowerCase();
      return (severity === "all" || finding.severity === severity) && text.includes(query.toLowerCase());
    });
  }, [selected, query, severity]);

  if (!selected) {
    return (
      <section className="surface p-5">
        <h2 className="text-lg font-semibold">No Scan Selected</h2>
        <p className="mt-1 text-sm text-slate-500">Start an assessment to populate posture, findings, evidence, and reports.</p>
      </section>
    );
  }

  return (
    <>
      <div className="grid gap-4 md:grid-cols-2 2xl:grid-cols-4">
        <Metric icon={<ShieldCheck size={18} />} label="Scans" value={metrics?.scans ?? 0} />
        <Metric icon={<Activity size={18} />} label="Open Findings" value={metrics?.open_findings ?? 0} />
        <Metric icon={<BarChart3 size={18} />} label="Posture" value={selected.posture_grade} />
        <Metric icon={<CheckCircle2 size={18} />} label="Pages Crawled" value={selected.pages_crawled} />
      </div>

      {activeView === "overview" ? (
        <>
          <SelectedScanHeader scan={selected} />
          <section className="grid gap-5 2xl:grid-cols-2">
            <Panel title="Severity Overview">
              <ResponsiveContainer width="100%" height={230}>
                <BarChart data={severityData}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis dataKey="name" />
                  <YAxis allowDecimals={false} />
                  <Tooltip />
                  <Bar dataKey="value" fill="#0f766e" radius={[4, 4, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </Panel>
            <Panel title="Attack Surface Growth">
              <ResponsiveContainer width="100%" height={230}>
                <AreaChart data={metrics?.dashboard.attack_surface_growth ?? []}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis dataKey="scan_id" />
                  <YAxis allowDecimals={false} />
                  <Tooltip />
                  <Area type="monotone" dataKey="routes" stackId="1" stroke="#0f766e" fill="#99f6e4" />
                  <Area type="monotone" dataKey="runtime_apis" stackId="1" stroke="#4f46e5" fill="#c7d2fe" />
                  <Area type="monotone" dataKey="endpoints" stackId="1" stroke="#b45309" fill="#fde68a" />
                </AreaChart>
              </ResponsiveContainer>
            </Panel>
          </section>
        </>
      ) : null}

      {activeView === "findings" ? (
        <Panel title="Findings">
          <div className="mb-4 flex flex-wrap gap-2">
            <input
              className="field min-w-72 flex-1"
              onChange={(event) => setQuery(event.target.value)}
              placeholder="Search findings, endpoints, evidence"
              value={query}
            />
            <select className="field w-40" onChange={(event) => setSeverity(event.target.value)} value={severity}>
              <option value="all">all severities</option>
              {severities.map((item) => (
                <option key={item} value={item}>
                  {item}
                </option>
              ))}
            </select>
          </div>
          <FindingList findings={filteredFindings} />
        </Panel>
      ) : null}

      {activeView === "surface" ? (
        <Panel title="Attack Surface">
          <Inventory inventory={selected.inventory} />
        </Panel>
      ) : null}

      {activeView === "reports" ? (
        <Panel title="Reports and Evidence">
          <ReportList scan={selected} />
        </Panel>
      ) : null}
    </>
  );
}

function SelectedScanHeader({ scan }: { scan: Scan }) {
  return (
    <section className="surface p-5">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <div className="mb-2 flex flex-wrap items-center gap-2">
            <StatusBadge status={scan.status} />
            <span className="badge border-slate-200 text-slate-600 dark:border-zinc-800 dark:text-slate-300">grade {scan.posture_grade}</span>
          </div>
          <h2 className="break-all text-xl font-semibold">{scan.target_url}</h2>
          <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">Created {new Date(scan.created_at).toLocaleString()}</p>
        </div>
        {scan.error ? (
          <div className="max-w-xl rounded-md border border-amber-200 bg-amber-50 p-3 text-sm text-amber-800 dark:border-amber-900 dark:bg-amber-950 dark:text-amber-100">
            {scan.error}
          </div>
        ) : null}
      </div>
    </section>
  );
}

function StatusBadge({ status }: { status: string }) {
  const className =
    status === "completed"
      ? "border-emerald-200 bg-emerald-50 text-emerald-700 dark:border-emerald-900 dark:bg-emerald-950 dark:text-emerald-200"
      : status === "failed"
        ? "border-red-200 bg-red-50 text-red-700 dark:border-red-900 dark:bg-red-950 dark:text-red-200"
        : "border-slate-200 bg-slate-50 text-slate-600 dark:border-zinc-800 dark:bg-zinc-900 dark:text-slate-300";
  return <span className={`badge ${className}`}>{status}</span>;
}
