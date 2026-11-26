import { useEffect, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { api } from "../api";
import { useApp } from "../store";
import { Chip, Empty, Err, Panel, PathChain, SEV, Score, Sev, btn, useLoad } from "../ui";

const cut = (s: string, n: number) => (s.length > n ? s.slice(0, n - 1) + "…" : s);

function Graph({ path }: { path: any }) {
  const W = 210, GAP = 120, H = 112, n = path.nodes.length, width = n * W + (n - 1) * GAP + 40;
  const x = (i: number) => 20 + i * (W + GAP);
  return (
    <div className="overflow-x-auto">
      <svg viewBox={`0 0 ${width} ${H + 50}`} style={{ minWidth: Math.min(width, 760) }} className="w-full" role="img"
        aria-label={`Attack path: ${path.nodes.map((v: any) => v.value).join(", then ")}`}>
        <defs><marker id="arr" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="7" markerHeight="7" orient="auto"><path d="M0 0L10 5L0 10z" fill={SEV.high} /></marker></defs>
        {path.edges.map((e: any, i: number) => (
          <g key={i}>
            <line className="flow" x1={x(i) + W} y1={64} x2={x(i + 1) - 4} y2={64} stroke={SEV.high} strokeWidth={3} markerEnd="url(#arr)" />
            <text x={x(i) + W + GAP / 2} y={50} textAnchor="middle" fontSize="11" fill="#475569">{e.relation.replace("_", " ")}</text>
            <title>{e.reason}</title>
          </g>))}
        {path.nodes.map((v: any, i: number) => {
          const role = v.role, stroke = role === "target" ? SEV.critical : role === "entry" ? SEV.high : "#94A3B8";
          return (
            <g key={v.asset_id} transform={`translate(${x(i)},12)`}>
              <rect width={W} height={H - 12} rx={8} fill="#fff" stroke={stroke} strokeWidth={role === "pivot" ? 1.5 : 2.5} />
              <text x={12} y={22} fontSize="11" fill="#64748B">{role === "entry" ? "Entry point" : role === "target" ? "Target" : "Pivot"}</text>
              <text x={12} y={42} fontSize="12.5" fontWeight="600" fill="#17232B" fontFamily="IBM Plex Mono, monospace">{cut(v.value.split(".")[0] + "." + (v.value.split(".")[1] ?? ""), 22)}<title>{v.value}</title></text>
              <text x={12} y={60} fontSize="11" fill="#475569">{v.exposure} · criticality {v.criticality}/5</text>
              {v.top_finding && <><circle cx={16} cy={78} r={5} fill={SEV[v.top_finding.severity]} /><text x={26} y={82} fontSize="11" fill="#17232B">{cut(v.top_finding.title, 27)}<title>{v.top_finding.title}</title></text></>}
            </g>);
        })}
      </svg>
    </div>
  );
}

export default function AttackPaths() {
  const { project } = useApp();
  const { id } = useParams();
  const nav = useNavigate();
  const list = useLoad(() => api(`/attack-paths?project_id=${project.id}`), [project.id]);
  const sel = id ? +id : list.data?.[0]?.id;
  const detail = useLoad(() => (sel ? api(`/attack-paths/${sel}`) : Promise.resolve(null)), [sel]);
  const [busy, setBusy] = useState(false); const [err, setErr] = useState<string | null>(null);
  useEffect(() => { if (!id && list.data?.[0]) nav(`/paths/${list.data[0].id}`, { replace: true }); }, [list.data]); // eslint-disable-line
  const analyze = async () => { setBusy(true); try { await api("/attack-paths/analyze", { body: { project_id: project.id } }); list.reload(); detail.reload(); } catch (e: any) { setErr(e.message); } finally { setBusy(false); } };
  const p = detail.data;
  return (
    <div className="space-y-5">
      <div className="flex items-center justify-between"><h1 className="text-xl font-semibold">Attack paths</h1><button className={btn} onClick={analyze} disabled={busy}>{busy ? "Analysing…" : "Analyse paths"}</button></div>
      <Err msg={err || list.error} />
      {list.data && !list.data.length ? <Panel><Empty>No attack paths found. A path needs an internet-facing asset with a medium or higher finding, a route to a business-critical asset (criticality 4 or 5), and a weakness on that target.</Empty></Panel> : (
        <div className="grid gap-5 lg:grid-cols-[320px_1fr]">
          <Panel title={`Paths (${list.data?.length ?? 0})`} className="self-start">
            <ul className="space-y-2">{list.data?.map((x: any) => (
              <li key={x.id}><Link to={`/paths/${x.id}`} className={`block rounded border p-2.5 ${sel === x.id ? "border-signal bg-teal-50" : "border-line hover:border-slate-400"}`}>
                <div className="mb-1 flex justify-between text-sm"><span>{x.hops} hop{x.hops > 1 ? "s" : ""}</span><Score v={x.risk_score} /></div><PathChain path={x} /></Link></li>))}</ul>
          </Panel>
          <div className="space-y-5">
            {p && <>
              <Panel title={<>Path #{p.id} <span className="ml-2 font-normal text-slate-500">risk <Score v={p.risk_score} /></span></>}><Graph path={p} /></Panel>
              <Panel title="Why this is risky">
                <ol className="space-y-2 text-sm leading-relaxed">{p.edges.length >= 0 && p.nodes.map((v: any, i: number) => (
                  <li key={v.asset_id} className="rounded bg-slate-50 p-2.5"><div className="flex flex-wrap items-center gap-2 font-medium"><Chip tone={v.role === "target" ? "bad" : v.role === "entry" ? "warn" : "mute"}>{v.role}</Chip><span className="font-mono text-xs">{v.value}</span></div>
                    {v.top_finding && <div className="mt-1"><Sev s={v.top_finding.severity} /> <Link className="text-signal hover:underline" to={`/findings/${v.top_finding.id}`}>{v.top_finding.title}</Link></div>}
                    {p.edges[i] && <div className="mt-1 text-slate-600">Then moves to <span className="font-mono text-xs">{p.nodes[i + 1].value}</span> via {p.edges[i].reason}.</div>}</li>))}</ol>
                <h3 className="mb-1 mt-4 text-sm font-semibold">How the path score is built</h3>
                <ul className="text-sm">{p.score_factors.map((x: any) => <li key={x.name} className="flex justify-between border-b border-line py-1"><span>{x.name} <span className="text-xs text-slate-500">({x.reason})</span></span><span className="font-mono">{x.points}</span></li>)}</ul>
              </Panel></>}
          </div>
        </div>)}
    </div>
  );
}
