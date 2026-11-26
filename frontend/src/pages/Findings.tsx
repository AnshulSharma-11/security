import { useState } from "react";
import { Link } from "react-router-dom";
import { api, qs } from "../api";
import { useApp } from "../store";
import { Chip, Empty, Err, Panel, STATUS_LABEL, Score, Sev, Table, btn2, input, statusTone, useLoad, when } from "../ui";

export default function Findings() {
  const { project } = useApp();
  const [f, setF] = useState({ severity: "", status: "", q: "", offset: 0 });
  const L = 25;
  const d = useLoad(() => api(`/findings?${qs({ project_id: project.id, ...f, limit: L })}`), [project.id, f]);
  const set = (k: string, v: any) => setF({ ...f, [k]: v, offset: 0 });
  return (
    <div className="space-y-5">
      <h1 className="text-xl font-semibold">Vulnerability center</h1>
      <Panel title={`Findings${d.data ? ` (${d.data.total})` : ""}`} actions={<div className="flex flex-wrap gap-2">
        <input aria-label="Search findings" className={input + " max-w-[14rem]"} placeholder="Search title or asset…" value={f.q} onChange={(e) => set("q", e.target.value)} />
        <select aria-label="Severity" className={input + " max-w-[9rem]"} value={f.severity} onChange={(e) => set("severity", e.target.value)}><option value="">Any severity</option>{["critical", "high", "medium", "low", "info"].map((s) => <option key={s}>{s}</option>)}</select>
        <select aria-label="Status" className={input + " max-w-[10rem]"} value={f.status} onChange={(e) => set("status", e.target.value)}><option value="">Any status</option>{Object.entries(STATUS_LABEL).map(([k, v]) => <option key={k} value={k}>{v}</option>)}</select></div>}>
        <Err msg={d.error} />
        {d.data && !d.data.items.length ? <Empty>No findings match these filters.</Empty> : (
          <Table head={["Risk", "Severity", "Finding", "Asset", "Status", "Assignee", "Last seen"]}>
            {d.data?.items.map((x: any) => (
              <tr key={x.id}><td className="px-2 py-2"><Score v={x.risk_score} /></td><td className="px-2"><Sev s={x.severity} /></td>
                <td className="px-2"><Link className="text-signal hover:underline" to={`/findings/${x.id}`}>{x.title}</Link>{x.cve && <span className="ml-1 font-mono text-xs text-slate-500">{x.cve}</span>}</td>
                <td className="px-2 font-mono text-xs">{x.asset}{x.port ? `:${x.port}` : ""}</td><td className="px-2"><Chip tone={statusTone(x.status)}>{STATUS_LABEL[x.status]}</Chip></td>
                <td className="px-2 text-xs">{x.assignee?.name ?? "–"}</td><td className="px-2 text-xs text-slate-600">{when(x.last_seen)}</td></tr>))}
          </Table>)}
        {d.data && d.data.total > L && (
          <div className="mt-3 flex items-center justify-between text-sm"><span>{f.offset + 1} to {Math.min(f.offset + L, d.data.total)} of {d.data.total}</span>
            <span className="flex gap-2"><button className={btn2} disabled={!f.offset} onClick={() => setF({ ...f, offset: f.offset - L })}>Previous</button><button className={btn2} disabled={f.offset + L >= d.data.total} onClick={() => setF({ ...f, offset: f.offset + L })}>Next</button></span></div>)}
      </Panel>
    </div>
  );
}
