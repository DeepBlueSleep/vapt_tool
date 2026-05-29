import type { ReactNode } from "react";

export function Metric({ icon, label, value }: { icon: ReactNode; label: string; value: string | number }) {
  return (
    <article className="surface p-4">
      <div className="mb-3 text-teal-700 dark:text-teal-300">{icon}</div>
      <div className="text-sm text-slate-500 dark:text-slate-400">{label}</div>
      <div className="mt-1 text-2xl font-semibold">{value}</div>
    </article>
  );
}

export function Panel({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="surface p-4">
      <h2 className="mb-3 text-base font-semibold">{title}</h2>
      {children}
    </section>
  );
}
