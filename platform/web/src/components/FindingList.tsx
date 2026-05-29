import type { Scan } from "../types";

export function FindingList({ findings }: { findings: Scan["findings"] }) {
  if (!findings.length) {
    return <p className="py-8 text-center text-sm text-slate-500">No findings match this filter.</p>;
  }
  return (
    <div className="space-y-2">
      {findings.map((finding) => (
        <details className="rounded-md border border-slate-200 p-3 dark:border-zinc-800" key={finding.id}>
          <summary className="cursor-pointer">
            <SeverityBadge severity={finding.severity} />
            <strong className="ml-2">{finding.title}</strong>
            <span className="ml-2 text-xs text-slate-500">{finding.occurrence_count} occurrence(s)</span>
          </summary>
          <div className="mt-3 grid gap-3 lg:grid-cols-3">
            <TextBlock title="Evidence" text={finding.evidence_summary} />
            <TextBlock title="Remediation" text={finding.remediation} />
            <TextBlock title="Affected" text={finding.url} />
          </div>
        </details>
      ))}
    </div>
  );
}

function TextBlock({ title, text }: { title: string; text: string }) {
  return (
    <div>
      <h3 className="mb-1 text-sm font-medium">{title}</h3>
      <p className="break-words text-sm leading-6 text-slate-600 dark:text-slate-300">{text}</p>
    </div>
  );
}

function SeverityBadge({ severity }: { severity: string }) {
  const className =
    severity === "critical"
      ? "border-red-900 bg-red-900 text-white"
      : severity === "high"
        ? "border-red-200 bg-red-50 text-red-700 dark:border-red-900 dark:bg-red-950 dark:text-red-200"
        : severity === "medium"
          ? "border-amber-200 bg-amber-50 text-amber-800 dark:border-amber-900 dark:bg-amber-950 dark:text-amber-200"
          : severity === "low"
            ? "border-blue-200 bg-blue-50 text-blue-700 dark:border-blue-900 dark:bg-blue-950 dark:text-blue-200"
            : "border-slate-200 bg-slate-50 text-slate-600 dark:border-zinc-800 dark:bg-zinc-900 dark:text-slate-300";
  return <span className={`badge ${className}`}>{severity}</span>;
}
