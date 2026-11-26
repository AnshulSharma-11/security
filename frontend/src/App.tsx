import { useEffect, useState } from "react";
import { NavLink, Navigate, Route, Routes, useNavigate } from "react-router-dom";
import { api, hasTokens, setTokens } from "./api";
import { AppCtx } from "./store";
import Login from "./pages/Login";
import Dashboard from "./pages/Dashboard";
import Assets from "./pages/Assets";
import ScanCenter from "./pages/ScanCenter";
import Findings from "./pages/Findings";
import FindingDetail from "./pages/FindingDetail";
import AttackPaths from "./pages/AttackPaths";
import Reports from "./pages/Reports";
import Admin from "./pages/Admin";

const NAV = [["/", "Dashboard"], ["/assets", "Attack surface"], ["/scans", "Scan center"], ["/findings", "Vulnerabilities"], ["/paths", "Attack paths"], ["/reports", "Reports"], ["/admin", "Administration"]];

export default function App() {
  const nav = useNavigate();
  const [user, setUser] = useState<any>(null);
  const [projects, setProjects] = useState<any[]>([]);
  const [project, setProjectState] = useState<any>(null);
  const [ready, setReady] = useState(false);
  const logout = () => { setTokens(null); sessionStorage.removeItem("sentinel.project"); setUser(null); setProjectState(null); nav("/login"); };
  const setProject = (p: any) => { setProjectState(p); sessionStorage.setItem("sentinel.project", String(p.id)); };

  useEffect(() => {
    const h = () => { setUser(null); nav("/login"); };
    window.addEventListener("sentinel:logout", h);
    if (!hasTokens()) { setReady(true); return () => window.removeEventListener("sentinel:logout", h); }
    Promise.all([api("/auth/me"), api("/projects")]).then(([u, ps]) => {
      setUser(u); setProjects(ps);
      setProjectState(ps.find((p: any) => String(p.id) === sessionStorage.getItem("sentinel.project")) ?? null);
    }).catch(() => setTokens(null)).finally(() => setReady(true));
    return () => window.removeEventListener("sentinel:logout", h);
  }, []);

  if (!ready) return <p className="p-8 text-sm text-slate-500">Loading…</p>;
  if (!user) return (
    <Routes>
      <Route path="/login" element={<Login onLogin={(u, ps, p) => { setUser(u); setProjects(ps); setProject(p); nav("/"); }} />} />
      <Route path="*" element={<Navigate to="/login" replace />} />
    </Routes>
  );
  if (!project) return <Login chooseOnly user={user} projects={projects} onLogin={(_u, _ps, p) => setProject(p)} />;

  return (
    <AppCtx.Provider value={{ user, projects, project, setProject, logout }}>
      <div className="flex min-h-screen">
        <aside className="hidden w-56 shrink-0 bg-harbor text-slate-200 md:block">
          <div className="px-5 py-5"><div className="text-lg font-semibold text-white">Sentinel</div><div className="text-xs text-teal-200/70">Nexavise Consulting</div></div>
          <nav className="flex flex-col gap-0.5 px-2" aria-label="Main">
            {NAV.map(([to, label]) => (
              <NavLink key={to} to={to} end={to === "/"} className={({ isActive }) => `rounded px-3 py-2 text-sm ${isActive ? "bg-white/15 font-medium text-white" : "hover:bg-white/10"}`}>{label}</NavLink>
            ))}
          </nav>
        </aside>
        <div className="min-w-0 flex-1">
          <header className="flex flex-wrap items-center justify-between gap-2 border-b border-line bg-white px-5 py-2.5">
            <div className="flex items-center gap-2 text-sm">
              <label htmlFor="proj" className="text-slate-500">Project</label>
              <select id="proj" className="rounded border border-line bg-white px-2 py-1" value={project.id} onChange={(e) => { setProject(projects.find((p) => p.id === +e.target.value)); nav("/"); }}>
                {projects.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
              </select>
            </div>
            <div className="flex items-center gap-3 text-sm"><span>{user.name} <span className="text-slate-500">({user.role})</span></span><button className="text-signal underline" onClick={logout}>Sign out</button></div>
          </header>
          <nav className="flex gap-3 overflow-x-auto border-b border-line bg-white px-4 py-2 text-sm md:hidden" aria-label="Main mobile">
            {NAV.map(([to, label]) => <NavLink key={to} to={to} end={to === "/"} className={({ isActive }) => (isActive ? "font-semibold text-signal" : "")}>{label}</NavLink>)}
          </nav>
          <main className="mx-auto max-w-7xl p-5">
            <Routes>
              <Route path="/" element={<Dashboard />} />
              <Route path="/assets" element={<Assets />} />
              <Route path="/scans" element={<ScanCenter />} />
              <Route path="/findings" element={<Findings />} />
              <Route path="/findings/:id" element={<FindingDetail />} />
              <Route path="/paths" element={<AttackPaths />} />
              <Route path="/paths/:id" element={<AttackPaths />} />
              <Route path="/reports" element={<Reports />} />
              <Route path="/admin" element={<Admin />} />
              <Route path="*" element={<Navigate to="/" replace />} />
            </Routes>
          </main>
        </div>
      </div>
    </AppCtx.Provider>
  );
}
