import { LogOut, Moon, RefreshCw, Sun } from "lucide-react";
import { useEffect, useMemo, useState } from "react";

import { useAuth } from "./auth";
import { AuthPanel } from "./components/AuthPanel";
import { Dashboard } from "./components/Dashboard";
import { ScanLauncher } from "./components/ScanLauncher";
import { ScanList } from "./components/ScanList";
import { usePlatformData } from "./hooks/usePlatformData";
import type { CreateScanRequest } from "./types";

type View = "overview" | "findings" | "surface" | "reports";

const views: { id: View; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "findings", label: "Findings" },
  { id: "surface", label: "Attack Surface" },
  { id: "reports", label: "Reports" }
];

export default function App() {
  const auth = useAuth();

  if (auth.loading && !auth.user) {
    return <main className="grid min-h-screen place-items-center bg-[#f4f6f8] text-sm text-slate-500 dark:bg-zinc-950 dark:text-slate-400">Loading session</main>;
  }

  if (!auth.user) {
    return <AuthPanel />;
  }

  return <AuthenticatedApp />;
}

function AuthenticatedApp() {
  const [dark, setDark] = useState(false);
  const [activeView, setActiveView] = useState<View>("overview");
  const auth = useAuth();
  const {
    scans,
    metrics,
    selected,
    selectedId,
    loading,
    error,
    setSelectedId,
    refresh,
    createScan,
    deleteScan,
    deleteAllScans
  } = usePlatformData();

  useEffect(() => {
    document.documentElement.classList.toggle("dark", dark);
  }, [dark]);

  const statusText = useMemo(() => {
    if (loading) return "Syncing";
    if (error) return "Attention needed";
    return `${scans.length} scan${scans.length === 1 ? "" : "s"}`;
  }, [error, loading, scans.length]);

  async function launchScan(payload: CreateScanRequest) {
    await createScan(payload);
    setActiveView("overview");
  }

  return (
    <main className="min-h-screen bg-[#f4f6f8] text-slate-950 dark:bg-zinc-950 dark:text-slate-100">
      <header className="sticky top-0 z-20 border-b border-slate-200 bg-white/95 px-5 py-4 backdrop-blur dark:border-zinc-800 dark:bg-zinc-950/95">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h1 className="text-xl font-semibold">Runtime Assessment Platform</h1>
            <p className="text-sm text-slate-500 dark:text-slate-400">
              {statusText} / {auth.environment.toUpperCase()} / {auth.user?.email}
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <select className="field w-auto" value={auth.environment} onChange={(event) => auth.setEnvironment(event.target.value === "prod" ? "prod" : "dev")}>
              <option value="dev">Dev DB</option>
              <option value="prod">Prod DB</option>
            </select>
            <button className="button-secondary" onClick={() => void refresh()} type="button">
              <RefreshCw size={16} />
              Refresh
            </button>
            <button className="button-secondary" onClick={auth.logout} type="button">
              <LogOut size={16} />
              Sign out
            </button>
            <button className="button-secondary px-2" onClick={() => setDark((value) => !value)} title="Toggle theme" type="button">
              {dark ? <Sun size={18} /> : <Moon size={18} />}
            </button>
          </div>
        </div>
      </header>

      <div className="grid gap-5 p-5 xl:grid-cols-[340px_1fr]">
        <aside className="space-y-4">
          <ScanLauncher disabled={loading} onCreate={launchScan} />
          <ScanList
            onDelete={deleteScan}
            onDeleteAll={deleteAllScans}
            onSelect={setSelectedId}
            scans={scans}
            selectedId={selectedId}
          />
        </aside>

        <section className="min-w-0 space-y-5">
          {error ? (
            <div className="surface border-red-200 bg-red-50 p-4 text-sm text-red-700 dark:border-red-900 dark:bg-red-950 dark:text-red-200">
              {error}
            </div>
          ) : null}

          <nav className="surface flex flex-wrap gap-1 p-1" aria-label="Dashboard sections">
            {views.map((view) => (
              <button
                className={`rounded-md px-3 py-2 text-sm font-medium transition ${
                  activeView === view.id
                    ? "bg-teal-700 text-white"
                    : "text-slate-600 hover:bg-slate-100 dark:text-slate-300 dark:hover:bg-zinc-900"
                }`}
                key={view.id}
                onClick={() => setActiveView(view.id)}
                type="button"
              >
                {view.label}
              </button>
            ))}
          </nav>

          <Dashboard activeView={activeView} metrics={metrics} selected={selected} />
        </section>
      </div>
    </main>
  );
}
