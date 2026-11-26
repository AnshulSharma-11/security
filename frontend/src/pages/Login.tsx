import { FormEvent, useState } from "react";
import { api, setTokens } from "../api";
import { Err, btn, input } from "../ui";

export default function Login({ onLogin, chooseOnly, user, projects }: { onLogin: (u: any, ps: any[], p: any) => void; chooseOnly?: boolean; user?: any; projects?: any[] }) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [session, setSession] = useState<{ user: any; projects: any[] } | null>(chooseOnly ? { user, projects: projects! } : null);

  async function submit(e: FormEvent) {
    e.preventDefault(); setBusy(true); setErr(null);
    try {
      const r = await api("/auth/login", { body: { email, password } });
      setTokens(r);
      if (r.projects.length === 0) setErr("Your organisation has no projects yet. Ask an administrator to create one.");
      else setSession({ user: r.user, projects: r.projects });
    } catch (e: any) { setErr(e.message); } finally { setBusy(false); }
  }
  return (
    <div className="grid min-h-screen md:grid-cols-[1fr_1.1fr]">
      <div className="flex flex-col justify-end bg-harbor p-10 text-slate-100">
        <p className="max-w-md text-3xl font-semibold leading-tight">What do we have, what is vulnerable, what matters most, and how do the weaknesses connect?</p>
        <p className="mt-4 max-w-md text-sm text-teal-100/70">Nexavise Sentinel only assesses assets that an administrator has approved for scanning.</p>
      </div>
      <div className="flex items-center justify-center p-8">
        {!session ? (
          <form onSubmit={submit} className="w-full max-w-sm space-y-4">
            <h1 className="text-2xl font-semibold">Sign in</h1>
            <Err msg={err} />
            <div><label htmlFor="email" className="mb-1 block text-sm">Email</label><input id="email" className={input} type="email" autoComplete="username" required value={email} onChange={(e) => setEmail(e.target.value)} /></div>
            <div><label htmlFor="pw" className="mb-1 block text-sm">Password</label><input id="pw" className={input} type="password" autoComplete="current-password" required value={password} onChange={(e) => setPassword(e.target.value)} /></div>
            <button className={`${btn} w-full`} disabled={busy}>{busy ? "Signing in…" : "Sign in"}</button>
          </form>
        ) : (
          <div className="w-full max-w-sm space-y-3">
            <h1 className="text-2xl font-semibold">Choose a project</h1>
            <p className="text-sm text-slate-600">Signed in as {session.user.name}. Assets and findings are isolated per project.</p>
            {session.projects.map((p) => (
              <button key={p.id} onClick={() => onLogin(session.user, session.projects, p)} className="block w-full rounded border border-line bg-white p-3 text-left hover:border-signal">
                <div className="font-medium">{p.name}</div><div className="text-sm text-slate-500">{p.description || "No description"}</div>
              </button>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
