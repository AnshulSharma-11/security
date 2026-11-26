import { ReactNode, useCallback, useEffect, useState } from "react";

export const SEV: Record<string, string> = { critical: "#9F1239", high: "#C2410C", medium: "#B7791F", low: "#2B6CB0", info: "#64748B" };
export const levelOf = (s: number) => (s >= 75 ? "critical" : s >= 55 ? "high" : s >= 35 ? "medium" : "low");
export const Sev = ({ s }: { s: string }) => (
  <span className="inline-block rounded px-2 py-0.5 text-xs font-medium text-white" style={{ background: SEV[s] ?? SEV.info }}>{s}</span>
);
const TONE: Record<string, string> = { ok: "bg-emerald-100 text-emerald-900", warn: "bg-amber-100 text-amber-900", bad: "bg-rose-100 text-rose-900", mute: "bg-slate-200 text-slate-700", info: "bg-sky-100 text-sky-900" };
export const Chip = ({ tone = "mute", children }: { tone?: string; children: ReactNode }) => (
  <span className={`inline-block rounded-full px-2 py-0.5 text-xs font-medium ${TONE[tone]}`}>{children}</span>
);
export const STATUS_LABEL: Record<string, string> = { open: "Open", confirmed: "Confirmed", false_positive: "False positive", accepted_risk: "Accepted risk", in_progress: "In progress", resolved: "Resolved" };
export const statusTone = (s: string) => ({ open: "bad", confirmed: "warn", in_progress: "info", resolved: "ok", false_positive: "mute", accepted_risk: "mute" } as any)[s] ?? "mute";
export const Score = ({ v }: { v: number | null | undefined }) =>
  v == null ? <span className="text-slate-400">–</span> : <span className="font-mono font-medium" style={{ color: SEV[levelOf(v)] }}>{Math.round(v)}</span>;

export const input = "w-full rounded border border-line bg-white px-2.5 py-1.5 text-sm";
export const btn = "rounded bg-signal px-3 py-1.5 text-sm font-medium text-white hover:bg-teal-800 disabled:opacity-50";
export const btn2 = "rounded border border-line bg-white px-3 py-1.5 text-sm font-medium hover:bg-slate-50 disabled:opacity-50";

export function Panel({ title, actions, children, className = "" }: { title?: ReactNode; actions?: ReactNode; children: ReactNode; className?: string }) {
  return (
    <section className={`rounded-md border border-line bg-white ${className}`}>
      {title && <header className="flex items-center justify-between border-b border-line px-4 py-2.5"><h2 className="text-sm font-semibold">{title}</h2><div className="flex gap-2">{actions}</div></header>}
      <div className="p-4">{children}</div>
    </section>
  );
}
export const Err = ({ msg }: { msg?: string | null }) => (msg ? <div role="alert" className="rounded border border-rose-300 bg-rose-50 px-3 py-2 text-sm text-rose-900">{msg}</div> : null);
export const Empty = ({ children }: { children: ReactNode }) => <p className="py-6 text-center text-sm text-slate-500">{children}</p>;

export function useLoad<T>(fn: () => Promise<T>, deps: any[]) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const run = useCallback(() => { setLoading(true); fn().then((d) => { setData(d); setError(null); }).catch((e) => setError(e.message)).finally(() => setLoading(false)); }, deps); // eslint-disable-line
  useEffect(run, [run]);
  return { data, error, loading, reload: run, setData };
}
export const when = (iso?: string | null) => (iso ? new Date(iso).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" }) : "never");

export function Table({ head, children }: { head: string[]; children: ReactNode }) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-left text-sm">
        <thead><tr className="border-b border-line text-xs text-slate-500">{head.map((h) => <th key={h} className="px-2 py-2 font-medium">{h}</th>)}</tr></thead>
        <tbody className="divide-y divide-line">{children}</tbody>
      </table>
    </div>
  );
}
export function PathChain({ path }: { path: any }) {
  return (
    <div className="flex flex-wrap items-center gap-1 text-xs">
      <span className="rounded bg-sev-high/10 px-1.5 py-0.5 font-mono">{path.entry}</span>
      <span className="text-slate-400">{"—".repeat(Math.max(1, path.hops))}&gt;</span>
      <span className="rounded bg-sev-critical/10 px-1.5 py-0.5 font-mono">{path.target}</span>
    </div>
  );
}
