import { FileText } from "lucide-react";

import type { Scan } from "../types";

export function ReportList({ scan }: { scan: Scan }) {
  return (
    <div className="space-y-4">
      <div className="space-y-2">
        {scan.reports.map((report) => (
          <a
            className="flex items-center gap-2 rounded-md border border-slate-200 p-3 text-sm hover:bg-slate-50 dark:border-zinc-800 dark:hover:bg-zinc-900"
            href={`/api/reports/${report.id}`}
            key={report.id}
            rel="noreferrer"
            target="_blank"
          >
            <FileText size={16} />
            <span>{report.title}</span>
            <span className="ml-auto text-xs text-slate-500">
              {report.audience} / {report.format}
            </span>
          </a>
        ))}
        {!scan.reports.length ? <p className="text-sm text-slate-500">No reports have been generated yet.</p> : null}
      </div>
      <div>
        <h3 className="mb-2 text-sm font-medium">Evidence</h3>
        <div className="grid grid-cols-2 gap-2">
          {scan.evidence.slice(0, 8).map((item) => (
            <div className="rounded-md border border-slate-200 p-2 text-sm dark:border-zinc-800" key={item.id}>
              <span className="block font-medium">{item.kind}</span>
              <span className="block truncate text-slate-500">{item.title}</span>
            </div>
          ))}
          {!scan.evidence.length ? <p className="col-span-2 text-sm text-slate-500">No evidence artifacts recorded.</p> : null}
        </div>
      </div>
    </div>
  );
}
