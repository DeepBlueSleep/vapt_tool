import { Trash2 } from "lucide-react";

import type { Scan } from "../types";

export function ScanList({
  scans,
  selectedId,
  onSelect,
  onDelete,
  onDeleteAll
}: {
  scans: Scan[];
  selectedId: number | null;
  onSelect: (id: number) => void;
  onDelete: (id: number) => Promise<void>;
  onDeleteAll: () => Promise<void>;
}) {
  return (
    <section className="surface p-3">
      <div className="mb-2 flex items-center justify-between gap-2">
        <h2 className="text-base font-semibold">Scans</h2>
        {scans.length ? (
          <button className="button-danger px-2 py-1" onClick={() => void onDeleteAll()} type="button">
            <Trash2 size={14} />
            Clear
          </button>
        ) : null}
      </div>
      <div className="max-h-[520px] space-y-1 overflow-auto">
        {scans.map((scan) => (
          <div
            className={`rounded-md border p-2 ${
              selectedId === scan.id ? "border-teal-300 bg-teal-50 dark:border-teal-800 dark:bg-teal-950" : "border-transparent"
            }`}
            key={scan.id}
          >
            <button className="w-full text-left" onClick={() => onSelect(scan.id)} type="button">
              <span className="block truncate text-sm font-medium">{scan.target_url}</span>
              <span className="mt-1 flex items-center gap-2 text-xs text-slate-500 dark:text-slate-400">
                <StatusBadge status={scan.status} />
                posture {scan.posture_grade}
              </span>
            </button>
            <button className="mt-2 text-xs text-red-600 dark:text-red-300" onClick={() => void onDelete(scan.id)} type="button">
              Delete scan
            </button>
          </div>
        ))}
        {!scans.length ? <p className="py-6 text-center text-sm text-slate-500">No scans yet.</p> : null}
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
