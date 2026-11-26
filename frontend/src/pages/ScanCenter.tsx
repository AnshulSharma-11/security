import { useEffect, useState } from "react";
import { api } from "../api";
import { useApp } from "../store";
import { Chip, Empty, Err, Panel, btn, btn2, useLoad, when } from "../ui";

const tone = (s: string) => ({ completed: "ok", failed: "bad", cancelled: "mute", running: "info", queued: "warn" } as any)[s] ?? "mute";

export default function ScanCenter() {
  const { project } = useApp();
  const assets = useLoad(() => api(`/assets?project_id=${project.id}`), [project.id]);
  const scans = useLoad(() => api(`/scans?project_id=${project.id}`), [project.id]);
  const [sel, setSel] = useState<number[]>([]);
  const [tools, setTools] = useState<string[]>(["nmap", "nuclei"]);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [open, setOpen] = useState<number | null>(null);
  const live = scans.data?.some((s: any) => s.status === "queued" || s.status === "running");
  useEffect(() => { if (!live) return; const t = setInterval(() => api(`/scans?project_id=${project.id}`).then(scans.setData).catch(() => {}), 2000); return () => clearInterval(t); }, [live, project.id]); // eslint-disable-line
  const toggle = (arr: any[], v: any) => (arr.includes(v) ? arr.filter((x) => x !== v) : [...arr, v]);
  const go = async (path: string, body: any) => { setBusy(true); setErr(null); try { const s = await api(path, { body }); setOpen(s.id); scans.reload(); assets.reload(); } catch (e: any) { setErr(e.message); } finally { setBusy(false); } };
  const ok = (assets.data ?? []).filter((a: any) => a.authorization_status === "approved");
  const pending = (assets.data ?? []).filter((a: any) => a.authorization_status !== "approved");
  return (
    <div className="space-y-5">
      <h1 className="text-xl font-semibold">Scan center</h1>
      <div className="grid gap-5 lg:grid-cols-[1fr_1.5fr]">
        <Panel title="New scan">
          <Err msg={err} />
          <fieldset className="mt-1"><legend className="mb-1 text-sm font-medium">Authorised targets</legend>
            {ok.length ? ok.map((a: any) => <label key={a.id} className="flex items-center gap-2 py-0.5 text-sm"><input type="checkbox" checked={sel.includes(a.id)} onChange={() => setSel(toggle(sel, a.id))} /><span className="font-mono text-xs">{a.value}</span></label>) : <Empty>No approved assets. Add one in Attack surface and have an administrator approve it.</Empty>}
            {pending.length > 0 && <p className="mt-2 text-xs text-slate-500">{pending.length} asset(s) cannot be scanned until an administrator approves them.</p>}
          </fieldset>
          <fieldset className="mt-4"><legend className="mb-1 text-sm font-medium">Scanners</legend>
            {[["nmap", "Nmap: service and version detection, risky exposed services"], ["nuclei", "Nuclei: template-based checks (non-destructive templates only)"]].map(([t, d]) => <label key={t} className="flex items-start gap-2 py-0.5 text-sm"><input className="mt-1" type="checkbox" checked={tools.includes(t)} onChange={() => setTools(toggle(tools, t))} />{d}</label>)}
          </fieldset>
          <div className="mt-4 flex flex-wrap gap-2">
            <button className={btn2} disabled={busy || !sel.length} onClick={() => go("/discovery", { project_id: project.id, asset_ids: sel })}>Run discovery</button>
            <button className={btn} disabled={busy || !sel.length || !tools.length} onClick={() => go("/scans", { project_id: project.id, asset_ids: sel, scanners: tools })}>Start scan</button>
          </div>
          <p className="mt-3 text-xs text-slate-500">Scans run in an isolated worker container, never in the web process. *.lab.sentinel.local targets are simulated and never touch the network.</p>
        </Panel>
        <Panel title="Scan history" actions={<button className={btn2} onClick={scans.reload}>Refresh</button>}>
          <Err msg={scans.error} />
          {scans.data && !scans.data.length ? <Empty>No scans yet. Pick a target and run discovery first.</Empty> : (
            <ul className="divide-y divide-line">{scans.data?.map((s: any) => (
              <li key={s.id} className="py-3">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <button className="text-left text-sm font-medium" aria-expanded={open === s.id} onClick={() => setOpen(open === s.id ? null : s.id)}>#{s.id} {s.kind === "discovery" ? "Discovery" : s.scanners.join(" + ")} <span className="font-normal text-slate-500">· {when(s.created_at)}</span></button>
                  <div className="flex items-center gap-2"><Chip tone={tone(s.status)}>{s.status}</Chip>{(s.status === "queued" || s.status === "running") && <button className="text-sm text-rose-700 underline" onClick={async () => { await api(`/scans/${s.id}/cancel`, { method: "POST" }).catch((e) => setErr(e.message)); scans.reload(); }}>Cancel</button>}</div>
                </div>
                <div className="mt-2 h-1.5 overflow-hidden rounded bg-slate-200" role="progressbar" aria-valuenow={s.progress} aria-valuemin={0} aria-valuemax={100}><div className="h-full bg-signal" style={{ width: `${s.progress}%` }} /></div>
                {open === s.id && <table className="mt-2 w-full text-xs"><tbody>{s.jobs.map((j: any) => <tr key={j.id} className="border-t border-line"><td className="py-1 font-mono">{j.asset}</td><td>{j.tool}</td><td><Chip tone={tone(j.status)}>{j.status}</Chip></td><td className="text-slate-600">{j.error ? j.error : j.tool === "discovery" ? "" : `${j.findings_created} new, ${j.findings_updated} repeated`}</td></tr>)}</tbody></table>}
              </li>))}</ul>)}
        </Panel>
      </div>
    </div>
  );
}
