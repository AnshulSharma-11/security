import { FormEvent, useState } from "react";
import { Link } from "react-router-dom";
import { api, qs } from "../api";
import { useApp } from "../store";
import { Chip, Empty, Err, Panel, STATUS_LABEL, Score, Sev, Table, btn, btn2, input, statusTone, useLoad, when } from "../ui";

const statusChip = (s: string) => <Chip tone={s === "active" ? "ok" : s === "inactive" ? "mute" : "warn"}>{s.replace("_", " ")}</Chip>;

function Detail({ id, others, reload }: { id: number; others: any[]; reload: () => void }) {
  const d = useLoad(() => api(`/assets/${id}`), [id]);
  const [to, setTo] = useState(""); const [rel, setRel] = useState("connects_to"); const [note, setNote] = useState(""); const [err, setErr] = useState<string | null>(null);
  if (!d.data) return <Err msg={d.error} />;
  const a = d.data;
  const link = async (e: FormEvent) => { e.preventDefault(); try { await api(`/assets/${id}/links`, { body: { target_asset_id: +to, relation: rel, note } }); setTo(""); setNote(""); setErr(null); d.reload(); reload(); } catch (x: any) { setErr(x.message); } };
  return (
    <div className="grid gap-4 bg-slate-50 p-4 lg:grid-cols-3">
      <div><h3 className="mb-1 text-sm font-semibold">Services</h3>
        {a.services.length ? <ul className="space-y-1 text-sm">{a.services.map((s: any) => <li key={s.id}><span className="font-mono">{s.port}/{s.protocol}</span> {s.service} <span className="text-slate-500">{[s.product, s.version].filter(Boolean).join(" ")}</span>{s.http_title && <div className="text-xs text-slate-500">HTTP {s.http_status}: {s.http_title}</div>}</li>)}</ul> : <p className="text-sm text-slate-500">Nothing discovered yet. Run discovery from the Scan center.</p>}
        <h3 className="mb-1 mt-3 text-sm font-semibold">DNS</h3>
        <pre className="whitespace-pre-wrap font-mono text-xs">{Object.entries(a.dns_info || {}).map(([k, v]: any) => `${k}: ${v.join(", ")}`).join("\n") || "no records"}</pre></div>
      <div><h3 className="mb-1 text-sm font-semibold">Findings</h3>
        {a.findings.length ? <ul className="space-y-1 text-sm">{a.findings.map((f: any) => <li key={f.id} className="flex items-center gap-2"><Sev s={f.severity} /><Link className="text-signal hover:underline" to={`/findings/${f.id}`}>{f.title}</Link></li>)}</ul> : <p className="text-sm text-slate-500">No findings.</p>}</div>
      <div><h3 className="mb-1 text-sm font-semibold">Relationships used for attack paths</h3>
        <ul className="space-y-1 text-sm">{a.links.map((l: any) => <li key={l.id} className="flex justify-between gap-2"><span><span className="font-mono text-xs">{l.src_value}</span> {l.relation.replace("_", " ")} <span className="font-mono text-xs">{l.dst_value}</span></span><button className="text-xs text-rose-700 underline" onClick={async () => { await api(`/assets/${id}/links/${l.id}`, { method: "DELETE" }); d.reload(); reload(); }}>Remove</button></li>)}</ul>
        <p className="mb-2 text-xs text-slate-500">Assets in the same /24 are linked automatically.</p>
        <form onSubmit={link} className="space-y-1.5"><Err msg={err} />
          <select aria-label="Target asset" className={input} value={to} onChange={(e) => setTo(e.target.value)} required><option value="">This asset can reach…</option>{others.filter((o) => o.id !== id).map((o) => <option key={o.id} value={o.id}>{o.value}</option>)}</select>
          <select aria-label="Relationship" className={input} value={rel} onChange={(e) => setRel(e.target.value)}>{["connects_to", "trusts", "credential_reuse", "network_adjacent", "hosts"].map((r) => <option key={r} value={r}>{r.replace("_", " ")}</option>)}</select>
          <input aria-label="Note" className={input} placeholder="Why (optional)" value={note} onChange={(e) => setNote(e.target.value)} maxLength={300} />
          <button className={btn2}>Add relationship</button></form></div>
    </div>
  );
}

export default function Assets() {
  const { project, user } = useApp();
  const [f, setF] = useState({ q: "", type: "", exposure: "", status: "", technology: "" });
  const list = useLoad(() => api(`/assets?${qs({ project_id: project.id, ...f })}`), [project.id, f]);
  const all = useLoad(() => api(`/assets?project_id=${project.id}`), [project.id, list.data?.length]);
  const [open, setOpen] = useState<number | null>(null);
  const [form, setForm] = useState({ value: "", criticality: 3, exposure: "unknown", authorization_note: "", confirm_authorized: false });
  const [err, setErr] = useState<string | null>(null);
  const add = async (e: FormEvent) => { e.preventDefault(); try { await api("/assets", { body: { project_id: project.id, ...form } }); setForm({ ...form, value: "", authorization_note: "", confirm_authorized: false }); setErr(null); list.reload(); } catch (x: any) { setErr(x.message); } };
  const patch = async (id: number, body: any) => { try { await api(`/assets/${id}`, { method: "PATCH", body }); list.reload(); } catch (x: any) { setErr(x.message); } };
  const Sel = ({ k, opts, label }: { k: string; opts: string[]; label: string }) => (
    <select aria-label={label} className={input + " max-w-[10rem]"} value={(f as any)[k]} onChange={(e) => setF({ ...f, [k]: e.target.value })}><option value="">{label}</option>{opts.map((o) => <option key={o}>{o}</option>)}</select>);
  return (
    <div className="space-y-5">
      <h1 className="text-xl font-semibold">Attack surface</h1>
      <Panel title="Add an asset to assess">
        <form onSubmit={add} className="grid gap-3 md:grid-cols-[2fr_1fr_1fr]">
          <div className="md:col-span-3"><Err msg={err} /></div>
          <div><label htmlFor="av" className="mb-1 block text-sm">Domain, hostname, IP or URL</label><input id="av" className={input} required value={form.value} onChange={(e) => setForm({ ...form, value: e.target.value })} placeholder="app.example.com or https://example.com/app" /></div>
          <div><label htmlFor="ac" className="mb-1 block text-sm">Business criticality (1 to 5)</label><select id="ac" className={input} value={form.criticality} onChange={(e) => setForm({ ...form, criticality: +e.target.value })}>{[1, 2, 3, 4, 5].map((n) => <option key={n}>{n}</option>)}</select></div>
          <div><label htmlFor="ae" className="mb-1 block text-sm">Exposure</label><select id="ae" className={input} value={form.exposure} onChange={(e) => setForm({ ...form, exposure: e.target.value })}><option value="unknown">Decide from discovery</option><option value="internet">Internet-facing</option><option value="internal">Internal only</option></select></div>
          <div className="md:col-span-2"><label htmlFor="an" className="mb-1 block text-sm">Authorisation reference (ticket, contract or owner)</label><input id="an" className={input} value={form.authorization_note} onChange={(e) => setForm({ ...form, authorization_note: e.target.value })} maxLength={500} /></div>
          <label className="flex items-start gap-2 text-sm md:col-span-3"><input type="checkbox" className="mt-1" checked={form.confirm_authorized} onChange={(e) => setForm({ ...form, confirm_authorized: e.target.checked })} /> I confirm my organisation owns this asset or has written permission to test it.{user.role !== "admin" && " An administrator must approve it before it can be scanned."}</label>
          <div><button className={btn}>Add asset</button></div>
        </form>
      </Panel>
      <Panel title={`Assets${list.data ? ` (${list.data.length})` : ""}`} actions={<div className="flex flex-wrap gap-2">
        <input aria-label="Search assets" className={input + " max-w-[12rem]"} placeholder="Search…" value={f.q} onChange={(e) => setF({ ...f, q: e.target.value })} />
        <Sel k="type" label="Any type" opts={["domain", "hostname", "ip", "url"]} /><Sel k="exposure" label="Any exposure" opts={["internet", "internal", "unknown"]} /><Sel k="status" label="Any status" opts={["active", "inactive", "needs_review"]} />
        <input aria-label="Technology" className={input + " max-w-[9rem]"} placeholder="Technology" value={f.technology} onChange={(e) => setF({ ...f, technology: e.target.value })} /></div>}>
        <Err msg={list.error} />
        {list.data && !list.data.length ? <Empty>No assets match. Add your first authorised asset above.</Empty> : (
          <Table head={["Asset", "Exposure", "Criticality", "Status", "Scan authorisation", "Technology", "Risk", "Last seen"]}>
            {list.data?.flatMap((a: any) => [
              <tr key={a.id} className="align-top">
                <td className="px-2 py-2"><button className="text-left font-mono text-xs text-signal hover:underline" aria-expanded={open === a.id} onClick={() => setOpen(open === a.id ? null : a.id)}>{a.value}</button><div className="text-xs text-slate-500">{a.type}{a.ip && a.ip !== a.value ? ` · ${a.ip}` : ""} · {a.services.length} services</div></td>
                <td className="px-2 py-2"><Chip tone={a.exposure === "internet" ? "bad" : "mute"}>{a.exposure}</Chip></td>
                <td className="px-2 py-2"><select aria-label={`Criticality of ${a.value}`} className="rounded border border-line bg-white px-1 py-0.5" value={a.criticality} onChange={(e) => patch(a.id, { criticality: +e.target.value })}>{[1, 2, 3, 4, 5].map((n) => <option key={n}>{n}</option>)}</select></td>
                <td className="px-2 py-2">{statusChip(a.status)}</td>
                <td className="px-2 py-2">{a.authorization_status === "approved" ? <Chip tone="ok">approved</Chip> : user.role === "admin" ? <button className={btn2} onClick={() => patch(a.id, { authorization_status: "approved" })}>Approve scanning</button> : <Chip tone="warn">{a.authorization_status}: waiting for an administrator</Chip>}</td>
                <td className="px-2 py-2 text-xs">{a.technologies.map((t: any) => [t.name, t.version].filter(Boolean).join(" ")).join(", ") || "–"}</td>
                <td className="px-2 py-2"><Score v={a.risk_score} /></td>
                <td className="px-2 py-2 text-xs text-slate-600">{when(a.last_seen)}</td>
              </tr>,
              open === a.id && <tr key={`${a.id}-d`}><td colSpan={8} className="p-0"><Detail id={a.id} others={all.data ?? []} reload={list.reload} /></td></tr>,
            ])}
          </Table>)}
      </Panel>
    </div>
  );
}
