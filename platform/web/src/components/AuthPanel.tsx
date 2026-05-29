import { Database, LockKeyhole } from "lucide-react";
import { useState, type FormEvent } from "react";

import { useAuth } from "../auth";

export function AuthPanel() {
  const { environment, setEnvironment, login, register, loading, error } = useAuth();
  const [mode, setMode] = useState<"login" | "register">("login");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (mode === "login") await login(email, password);
    else await register(email, password);
  }

  return (
    <main className="grid min-h-screen place-items-center bg-[#eef2f7] p-5 text-slate-950 dark:bg-zinc-950 dark:text-slate-100">
      <section className="surface w-full max-w-md p-5">
        <div className="mb-5 flex items-center gap-3">
          <span className="grid h-10 w-10 place-items-center rounded-lg bg-teal-700 text-white">
            <LockKeyhole size={20} />
          </span>
          <div>
            <h1 className="text-xl font-semibold">Runtime Assessment</h1>
            <p className="text-sm text-slate-500 dark:text-slate-400">NeonDB-backed Cloudflare Worker</p>
          </div>
        </div>

        <div className="mb-4 grid grid-cols-2 gap-2 rounded-md bg-slate-100 p-1 dark:bg-zinc-900">
          <button className={`rounded px-3 py-2 text-sm font-medium ${mode === "login" ? "bg-white shadow-sm dark:bg-zinc-800" : ""}`} onClick={() => setMode("login")} type="button">
            Sign in
          </button>
          <button className={`rounded px-3 py-2 text-sm font-medium ${mode === "register" ? "bg-white shadow-sm dark:bg-zinc-800" : ""}`} onClick={() => setMode("register")} type="button">
            Register
          </button>
        </div>

        <label className="mb-4 block text-sm">
          <span className="mb-1 flex items-center gap-2 font-medium text-slate-600 dark:text-slate-300">
            <Database size={15} />
            Environment
          </span>
          <select className="field" value={environment} onChange={(event) => setEnvironment(event.target.value === "prod" ? "prod" : "dev")}>
            <option value="dev">Development NeonDB</option>
            <option value="prod">Production NeonDB</option>
          </select>
        </label>

        <form className="space-y-4" onSubmit={submit}>
          <input className="field" autoComplete="email" name="email" onChange={(event) => setEmail(event.target.value)} placeholder="Email" required type="email" value={email} />
          <input
            className="field"
            autoComplete={mode === "login" ? "current-password" : "new-password"}
            minLength={10}
            name="password"
            onChange={(event) => setPassword(event.target.value)}
            placeholder="Password"
            required
            type="password"
            value={password}
          />
          {error ? <p className="rounded-md border border-red-200 bg-red-50 p-3 text-sm text-red-700 dark:border-red-900 dark:bg-red-950 dark:text-red-200">{error}</p> : null}
          <button className="button-primary w-full" disabled={loading} type="submit">
            {loading ? "Working" : mode === "login" ? "Sign in" : "Create account"}
          </button>
        </form>
      </section>
    </main>
  );
}
