const inventoryKeys = ["runtime_apis", "endpoints", "browser_routes", "pages", "parameters", "auth_signals", "expanded_attack_surface"];

export function Inventory({ inventory }: { inventory: Record<string, string[]> }) {
  return (
    <div className="space-y-2">
      {inventoryKeys.map((key) => (
        <details className="rounded-md border border-slate-200 p-3 dark:border-zinc-800" key={key}>
          <summary className="cursor-pointer text-sm font-medium">
            {key.replaceAll("_", " ")} <span className="badge ml-1 border-slate-200 text-slate-500 dark:border-zinc-800">{inventory[key]?.length ?? 0}</span>
          </summary>
          <ul className="mt-2 max-h-64 overflow-auto text-sm text-slate-600 dark:text-slate-300">
            {(inventory[key] ?? []).slice(0, 100).map((item) => (
              <li className="break-all border-b border-slate-100 py-1 dark:border-zinc-900" key={item}>
                {item}
              </li>
            ))}
          </ul>
        </details>
      ))}
    </div>
  );
}
