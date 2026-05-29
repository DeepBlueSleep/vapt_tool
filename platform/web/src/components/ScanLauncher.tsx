import { Loader2, Play } from "lucide-react";
import { useState } from "react";

import type { CreateScanRequest } from "../types";

export function ScanLauncher({ onCreate, disabled }: { onCreate: (payload: CreateScanRequest) => Promise<void>; disabled: boolean }) {
  const [target, setTarget] = useState("");
  const [browser, setBrowser] = useState(true);
  const [active, setActive] = useState(false);

  return (
    <section className="surface p-4">
      <h2 className="text-base font-semibold">Start Scan</h2>
      <div className="mt-4 space-y-3">
        <label className="block">
          <span className="mb-1 block text-sm font-medium text-slate-600 dark:text-slate-300">Target URL</span>
          <input className="field" onChange={(event) => setTarget(event.target.value)} placeholder="https://example.com" value={target} />
        </label>
        <div className="grid grid-cols-2 gap-2">
          <label className="flex items-center gap-2 text-sm">
            <input checked={browser} onChange={(event) => setBrowser(event.target.checked)} type="checkbox" />
            Runtime
          </label>
          <label className="flex items-center gap-2 text-sm">
            <input checked={active} onChange={(event) => setActive(event.target.checked)} type="checkbox" />
            Active checks
          </label>
        </div>
        <button
          className="button-primary w-full"
          disabled={disabled || !target.trim()}
          onClick={() =>
            void onCreate({
              url: target.trim(),
              max_depth: 1,
              max_pages: 50,
              request_budget: 80,
              enable_browser: browser,
              enable_active_checks: active,
              capture_screenshots: true,
              enable_attack_surface_expansion: true,
              enable_framework_expansion: true,
              enable_predictable_locations: true,
              enable_api_expansion: true,
              enable_runtime_expansion: true
            })
          }
          type="button"
        >
          {disabled ? <Loader2 className="animate-spin" size={16} /> : <Play size={16} />}
          Launch Assessment
        </button>
      </div>
    </section>
  );
}
