import { Link } from "react-router-dom";
import { api } from "../api";
import { useApp } from "../store";
import { Chip, Empty, Err, Panel, PathChain, SEV, Score, Sev, Table, levelOf, useLoad } from "../ui";

function Trend({ pts }: { pts: { date: string; score: number }[] }) {
  if (pts.length < 2) return <p className="text-xs text-slate-500">Trend appears after a second day of scoring.</p>;
  const w = 260, h = 56, max = Math.max(...pts.map((p) => p.score), 1);
  const xy = pts.map((p, i) => `${(i / (pts.length - 1)) * w},${h - (p.score / max) * (h - 6) - 3}`).join(" ");
  return (
    <svg viewBox={`0 0 ${w} ${h}`} className="w-full max-w-xs" role="img" aria-label={`Risk trend over ${pts.length} days, latest ${pts[pts.length - 1].score}`}>
      <polyline points={xy} fill="none" stroke="#0E7C86" strokeWidth="2" /><title>Risk trend</title>
    </svg>
  );
}

export default function Dashboard() {
  const { project } = useApp();
  const ov = useLoad(() => api(`/risk/overview?project_id=${project.id}`), [project.id]);
  const top = useLoad(() => api(`/risk/top?project_id=${project.id}&limit=6`), [project.id]);
  const o = ov.data;
  if (ov.error) return <Err msg={ov.error} />;
  if (!o) return <p className="text-sm text-slate-500">Loading…</p>;
  const best = o.top_paths[0];
  return (
    <div className="space-y-5">
      <h1 className="text-xl font-semibold">{project.name}</h1>
      <div className="grid gap-4 lg:grid-cols-[1fr_1.4fr]">
        <Panel title="Project risk">
          <div className="flex items-end gap-3"><span className="text-5xl font-semibold" style={{ color: SEV[levelOf(o.risk_score)] }}>{Math.round(o.risk_score)}</span><span className="pb-1 text-sm text-slate-600">out of 100, {o.level}</span></div>
          <div className="relative mt-3 flex h-2 overflow-hidden rounded" aria-hidden>
            {[35, 20, 20, 25].map((w, i) => <div key={i} style={{ width: `${w}%`, background: ["#2B6CB0", "#B7791F", "#C2410C", "#9F1239"][i], opacity: 0.55 }} />)}
            <div className="absolute top-0 h-2 w-1 bg-ink" style={{ left: `${Math.min(o.risk_score, 99)}%` }} />
          </div>
          <div className="mt-4"><Trend pts={o.trend} /></div>
        </Panel>
        <Panel title="Most dangerous attack path" actions={best && <Link className="text-sm text-signal underline" to={`/paths/${best.id}`}>Open path</Link>}>
          {best ? (<><PathChain path={best} /><p className="mt-3 text-sm leading-relaxed text-slate-700">{best.explanation}</p><p className="mt-2 text-sm">Path risk <Score v={best.risk_score} /> across {best.hops} hops.</p></>)
            : <Empty>No attack path yet. Run discovery and scans, then analyse paths.</Empty>}
        </Panel>
      </div>
      <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
        {[["Assets", o.total_assets], ["Critical and high findings", o.critical_high], ["Active findings", o.active_findings], ["Awaiting scan approval", o.pending_authorization]].map(([l, v]) => (
          <div key={l as string} className="rounded-md border border-line bg-white px-4 py-3"><div className="text-2xl font-semibold">{v}</div><div className="text-sm text-slate-600">{l}</div></div>
        ))}
      </div>
      <div className="grid gap-4 lg:grid-cols-2">
        <Panel title="Highest-risk assets">
          {top.data?.assets.length ? (
            <Table head={["Asset", "Criticality", "Exposure", "Risk"]}>
              {top.data.assets.map((a: any) => <tr key={a.id}><td className="px-2 py-2 font-mono text-xs">{a.value}</td><td className="px-2">{a.criticality}/5</td><td className="px-2"><Chip tone={a.exposure === "internet" ? "bad" : "mute"}>{a.exposure}</Chip></td><td className="px-2"><Score v={a.risk_score} /></td></tr>)}
            </Table>) : <Empty>No scored assets yet.</Empty>}
        </Panel>
        <Panel title="Highest-risk findings" actions={<Link className="text-sm text-signal underline" to="/findings">All findings</Link>}>
          {top.data?.findings.length ? (
            <Table head={["Risk", "Severity", "Finding", "Asset"]}>
              {top.data.findings.map((f: any) => <tr key={f.id}><td className="px-2 py-2"><Score v={f.risk_score} /></td><td className="px-2"><Sev s={f.severity} /></td><td className="px-2"><Link className="text-signal hover:underline" to={`/findings/${f.id}`}>{f.title}</Link></td><td className="px-2 font-mono text-xs">{f.asset}</td></tr>)}
            </Table>) : <Empty>No findings yet.</Empty>}
        </Panel>
      </div>
    </div>
  );
}
