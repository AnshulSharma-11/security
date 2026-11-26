import { FormEvent, useState } from "react";
import { api } from "../api";
import { useApp } from "../store";
import { Chip, Empty, Err, Panel, Table, btn, btn2, input, useLoad, when } from "../ui";

function Users() {
  const u = useLoad(() => api("/admin/users"), []);
  const [f, setF] = useState({ email: "", name: "", password: "", role: "analyst" }); const [err, setErr] = useState<string | null>(null);
  const add = async (e: FormEvent) => { e.preventDefault(); try { await api("/admin/users", { body: f }); setF({ email: "", name: "", password: "", role: "analyst" }); setErr(null); u.reload(); } catch (x: any) { setErr(x.message); } };
  const patch = async (id: number, body: any) => { try { await api(`/admin/users/${id}`, { method: "PATCH", body }); u.reload(); } catch (x: any) { setErr(x.message); } };
  return (
    <div className="grid gap-5 lg:grid-cols-[1.6fr_1fr]">
      <Panel title="Users"><Err msg={u.error} />
        <Table head={["Name", "Email", "Role", "Status", "Last sign-in", ""]}>{u.data?.map((x: any) => (
          <tr key={x.id}><td className="px-2 py-2">{x.name}</td><td className="px-2 text-xs">{x.email}</td>
            <td className="px-2"><select aria-label={`Role of ${x.name}`} className="rounded border border-line bg-white px-1 py-0.5" value={x.role} onChange={(e) => patch(x.id, { role: e.target.value })}><option>admin</option><option>analyst</option></select></td>
            <td className="px-2"><Chip tone={x.is_active ? "ok" : "mute"}>{x.is_active ? "active" : "disabled"}</Chip></td><td className="px-2 text-xs">{when(x.last_login)}</td>
            <td className="px-2"><button className="text-sm text-signal underline" onClick={() => patch(x.id, { is_active: !x.is_active })}>{x.is_active ? "Disable" : "Enable"}</button></td></tr>))}</Table></Panel>
      <Panel title="Add a user" className="self-start"><form onSubmit={add} className="space-y-2"><Err msg={err} />
        <input aria-label="Name" className={input} placeholder="Full name" required value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} />
        <input aria-label="Email" className={input} type="email" placeholder="Email" required value={f.email} onChange={(e) => setF({ ...f, email: e.target.value })} />
        <input aria-label="Initial password" className={input} type="password" placeholder="Initial password (10+ characters)" minLength={10} required value={f.password} onChange={(e) => setF({ ...f, password: e.target.value })} autoComplete="new-password" />
        <select aria-label="Role" className={input} value={f.role} onChange={(e) => setF({ ...f, role: e.target.value })}><option value="analyst">Analyst: triage and scan approved assets</option><option value="admin">Admin: approve scanning, manage users</option></select>
        <button className={btn}>Create user</button></form></Panel>
    </div>
  );
}
function Audit() {
  const [action, setAction] = useState("");
  const a = useLoad(() => api(`/admin/audit-logs?limit=200${action ? `&action=${encodeURIComponent(action)}` : ""}`), [action]);
  return (
    <Panel title="Audit log" actions={<select aria-label="Filter by action" className={input + " max-w-[11rem]"} value={action} onChange={(e) => setAction(e.target.value)}><option value="">All actions</option>{["auth", "asset", "assessment", "discovery", "scan", "finding", "report", "user", "project", "attackpath"].map((x) => <option key={x}>{x}</option>)}</select>}>
      <Err msg={a.error} />{a.data && !a.data.length ? <Empty>No entries.</Empty> : <Table head={["When", "User", "Action", "Detail", "IP"]}>{a.data?.map((r: any) => <tr key={r.id}><td className="whitespace-nowrap px-2 py-1.5 text-xs">{when(r.at)}</td><td className="px-2 text-xs">{r.user ?? "–"}</td><td className="px-2 font-mono text-xs">{r.action}</td><td className="px-2 text-xs">{r.detail}</td><td className="px-2 font-mono text-xs">{r.ip ?? ""}</td></tr>)}</Table>}
    </Panel>);
}
function Integrations() {
  const i = useLoad(() => api("/admin/integrations"), []);
  if (!i.data) return <Err msg={i.error} />;
  return (
    <Panel title="Integrations" actions={<button className={btn2} onClick={i.reload}>Re-check</button>}>
      <p className="mb-3 text-sm">Worker: <Chip tone={i.data.worker === "online" ? "ok" : "bad"}>{i.data.worker}</Chip> · Queue: {i.data.queue}</p>
      <Table head={["Tool", "Purpose", "Installed in worker"]}>{i.data.tools.map((t: any) => <tr key={t.name}><td className="px-2 py-2 font-mono">{t.name}</td><td className="px-2">{t.purpose}</td><td className="px-2"><Chip tone={t.installed ? "ok" : "bad"}>{t.installed ? "yes" : "no"}</Chip></td></tr>)}</Table>
    </Panel>);
}

export default function Admin() {
  const { user } = useApp();
  const [tab, setTab] = useState("users");
  if (user.role !== "admin") return <Panel><Empty>Administration is limited to users with the admin role.</Empty></Panel>;
  return (
    <div className="space-y-5"><h1 className="text-xl font-semibold">Administration</h1>
      <div role="tablist" className="flex gap-1 border-b border-line">{[["users", "Users and roles"], ["audit", "Audit log"], ["int", "Integrations"]].map(([k, l]) => <button key={k} role="tab" aria-selected={tab === k} onClick={() => setTab(k)} className={`px-3 py-2 text-sm ${tab === k ? "border-b-2 border-signal font-semibold" : "text-slate-600"}`}>{l}</button>)}</div>
      {tab === "users" ? <Users /> : tab === "audit" ? <Audit /> : <Integrations />}
    </div>);
}
