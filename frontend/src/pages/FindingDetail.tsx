import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { api } from "../api";
import { useApp } from "../store";
import { Chip, Err, Panel, STATUS_LABEL, Score, Sev, btn, input, statusTone, useLoad, when } from "../ui";

export default function FindingDetail() {
  const { id } = useParams();
  const { user } = useApp();
  const d = useLoad(() => api(`/findings/${id}`), [id]);
  const users = useLoad(() => api("/users"), []);
  const [status, setStatus] = useState(""); const [note, setNote] = useState(""); const [err, setErr] = useState<string | null>(null);
  useEffect(() => { if (d.data) setStatus(d.data.status); }, [d.data?.status]); // eslint-disable-line
  if (d.error) return <Err msg={d.error} />;
  const f = d.data; if (!f) return <p className="text-sm text-slate-500">Loading…</p>;
  const save = async () => { try { d.setData(await api(`/findings/${id}`, { method: "PATCH", body: { status, note } })); setNote(""); setErr(null); d.reload(); } catch (e: any) { setErr(e.message); } };
  const assign = async (v: string) => { try { d.setData(await api(`/findings/${id}/assign`, { body: { user_id: v ? +v : null } })); setErr(null); } catch (e: any) { setErr(e.message); } };
  return (
    <div className="space-y-5">
      <div><Link className="text-sm text-signal underline" to="/findings">All vulnerabilities</Link>
        <h1 className="mt-1 flex flex-wrap items-center gap-2 text-xl font-semibold"><Sev s={f.severity} />{f.title}</h1>
        <p className="text-sm text-slate-600">on <span className="font-mono">{f.asset}{f.port ? `:${f.port}` : ""}</span>{f.cve && <> · <span className="font-mono">{f.cve}</span></>} · first seen {when(f.first_seen)} · seen {f.occurrences}x</p></div>
      <div className="grid gap-5 lg:grid-cols-[1.6fr_1fr]">
        <div className="space-y-5">
          <Panel title="What it is"><p className="whitespace-pre-wrap text-sm leading-relaxed">{f.description || "No description provided by the scanner."}</p>{f.references.length > 0 && <ul className="mt-3 list-disc pl-5 text-xs text-slate-600">{f.references.map((r: string) => <li key={r} className="break-all">{r}</li>)}</ul>}</Panel>
          <Panel title="Remediation"><p className="whitespace-pre-wrap text-sm leading-relaxed">{f.remediation}</p></Panel>
          <Panel title="Technical evidence">{f.evidence.map((e: any) => <div key={e.id} className="mb-3"><div className="mb-1 text-xs text-slate-500">{e.tool} · {when(e.at)}</div><pre className="overflow-x-auto whitespace-pre-wrap break-words rounded border-l-4 border-signal bg-slate-50 p-3 font-mono text-xs">{e.content}</pre></div>)}</Panel>
          <Panel title="Status history"><ul className="space-y-2 text-sm">{f.history.map((h: any, i: number) => <li key={i}>{h.old ? `${STATUS_LABEL[h.old]} to ` : "Created as "}<strong>{STATUS_LABEL[h.new]}</strong> by {h.by} <span className="text-slate-500">· {when(h.at)}</span>{h.note && <div className="text-slate-600">“{h.note}”</div>}</li>)}</ul></Panel>
        </div>
        <div className="space-y-5">
          <Panel title="Why this score">
            <div className="mb-3 flex items-baseline gap-2"><span className="text-4xl font-semibold"><Score v={f.risk_score} /></span><span className="text-sm text-slate-600">out of 100</span></div>
            <ul className="space-y-2.5">{f.risk_factors.map((x: any) => (
              <li key={x.name}><div className="flex justify-between text-sm"><span>{x.name}</span><span className="font-mono">{x.points > 0 ? "+" : ""}{x.points}{x.max ? ` / ${x.max}` : ""}</span></div>
                {x.max > 0 && <div className="mt-0.5 h-1.5 rounded bg-slate-200"><div className="h-full rounded bg-signal" style={{ width: `${(x.points / x.max) * 100}%` }} /></div>}
                <div className="text-xs text-slate-500">{x.reason}</div></li>))}</ul>
          </Panel>
          <Panel title="Triage">
            <Err msg={err} />
            <div className="space-y-2">
              <div><label htmlFor="st" className="mb-1 block text-sm">Status</label><select id="st" className={input} value={status} onChange={(e) => setStatus(e.target.value)}>{Object.entries(STATUS_LABEL).map(([k, v]) => <option key={k} value={k} disabled={k === "accepted_risk" && user.role !== "admin"}>{v}{k === "accepted_risk" && user.role !== "admin" ? " (admin only)" : ""}</option>)}</select></div>
              <div><label htmlFor="nt" className="mb-1 block text-sm">Note</label><input id="nt" className={input} value={note} onChange={(e) => setNote(e.target.value)} maxLength={500} placeholder="Why are you changing the status?" /></div>
              <button className={btn} onClick={save} disabled={status === f.status}>Save status</button>
              <div className="pt-2"><label htmlFor="as" className="mb-1 block text-sm">Assigned to</label><select id="as" className={input} value={f.assignee?.id ?? ""} onChange={(e) => assign(e.target.value)}><option value="">Unassigned</option>{users.data?.map((u: any) => <option key={u.id} value={u.id}>{u.name}</option>)}</select></div>
              <div className="pt-1"><Chip tone={statusTone(f.status)}>{STATUS_LABEL[f.status]}</Chip></div>
            </div>
          </Panel>
        </div>
      </div>
    </div>
  );
}
