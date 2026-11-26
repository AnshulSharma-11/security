import { useState } from "react";
import { api } from "../api";
import { useApp } from "../store";
import { Empty, Err, Panel, btn, btn2, useLoad, when } from "../ui";

export default function Reports() {
  const { project } = useApp();
  const list = useLoad(() => api(`/reports?project_id=${project.id}`), [project.id]);
  const [view, setView] = useState<any>(null); const [err, setErr] = useState<string | null>(null); const [busy, setBusy] = useState(false);
  const make = async (kind: string) => { setBusy(true); setErr(null); try { const r = await api("/reports", { body: { project_id: project.id, kind } }); list.reload(); open(r.id); } catch (e: any) { setErr(e.message); } finally { setBusy(false); } };
  const open = async (id: number) => { try { setView(await api(`/reports/${id}`)); } catch (e: any) { setErr(e.message); } };
  const download = async (id: number) => { const r = await api(`/reports/${id}/download`, { raw: true }); const u = URL.createObjectURL(await r.blob()); const a = document.createElement("a"); a.href = u; a.download = `sentinel-report-${id}.html`; a.click(); URL.revokeObjectURL(u); };
  return (
    <div className="space-y-5">
      <h1 className="text-xl font-semibold">Reports</h1>
      <Err msg={err || list.error} />
      <div className="grid gap-5 lg:grid-cols-[320px_1fr]">
        <Panel title="Generate" className="self-start">
          <div className="flex flex-col gap-2"><button className={btn} disabled={busy} onClick={() => make("executive")}>Executive summary</button><button className={btn2} disabled={busy} onClick={() => make("technical")}>Technical vulnerability report</button></div>
          <h3 className="mb-1 mt-5 text-sm font-semibold">Previous reports</h3>
          {list.data && !list.data.length ? <Empty>No reports yet.</Empty> : <ul className="space-y-1 text-sm">{list.data?.map((r: any) => <li key={r.id}><button className={`text-left hover:underline ${view?.id === r.id ? "font-semibold" : "text-signal"}`} onClick={() => open(r.id)}>{r.kind === "executive" ? "Executive" : "Technical"} · {when(r.created_at)}</button></li>)}</ul>}
        </Panel>
        <Panel title={view ? view.title : "Preview"} actions={view && <button className={btn2} onClick={() => download(view.id)}>Download HTML</button>}>
          {view ? <iframe title="Report preview" sandbox="" srcDoc={view.content} className="h-[70vh] w-full rounded border border-line bg-white" /> : <Empty>Generate or choose a report to preview it here.</Empty>}
        </Panel>
      </div>
    </div>
  );
}
