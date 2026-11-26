"""HTML report generation. Every dynamic value goes through html.escape; reports contain no scripts."""
import html
from sqlalchemy.orm import Session
from .attackpath import path_dict
from .models import Asset, AttackPath, Project, now
from .risk import active_findings, asset_risks, level, project_score

e = lambda x: html.escape("" if x is None else str(x))  # noqa: E731
CSS = """body{font:14px/1.5 'Segoe UI',system-ui,sans-serif;color:#1d2433;max-width:900px;margin:32px auto;padding:0 20px}
h1{font-size:26px;margin:0}h2{border-bottom:2px solid #0e7c86;padding-bottom:4px;margin-top:32px}
table{border-collapse:collapse;width:100%;margin:8px 0}th,td{border:1px solid #d5dbe3;padding:6px 8px;text-align:left;vertical-align:top}
th{background:#eef2f6}pre{background:#f3f5f7;padding:10px;white-space:pre-wrap;word-break:break-word;border-left:3px solid #0e7c86}
.s{display:inline-block;padding:1px 8px;border-radius:10px;color:#fff;font-size:12px}.critical{background:#9f1239}.high{background:#c2410c}
.medium{background:#b7791f}.low{background:#2b6cb0}.info{background:#64748b}.muted{color:#64748b}.score{font-size:40px;font-weight:700}"""


def _sev(s):
    return f'<span class="s {e(s)}">{e(s)}</span>'


def build(db: Session, project: Project, kind: str) -> tuple[str, str]:
    act = sorted(active_findings(db, project.id), key=lambda f: f.risk_score, reverse=True)
    sc = project_score(db, project.id)
    risks = asset_risks(db, project.id)
    assets = {a.id: a for a in db.query(Asset).filter_by(project_id=project.id)}
    paths = db.query(AttackPath).filter_by(project_id=project.id).order_by(AttackPath.risk_score.desc()).all()
    title = f"{'Executive Summary' if kind == 'executive' else 'Technical Vulnerability Report'} - {project.name}"
    counts = {s: sum(f.severity == s for f in act) for s in ("critical", "high", "medium", "low", "info")}
    h = [f"<!doctype html><html><head><meta charset='utf-8'><title>{e(title)}</title><style>{CSS}</style></head><body>",
         f"<h1>{e(title)}</h1><p class='muted'>Generated {e(now().strftime('%Y-%m-%d %H:%M UTC'))} by Nexavise Sentinel</p>",
         f"<h2>Overall risk</h2><div class='score'>{sc:.0f}<span class='muted' style='font-size:16px'> / 100 ({e(level(sc))})</span></div>",
         f"<p>{len(assets)} assets in scope, {len(act)} active findings: " + ", ".join(f"{n} {s}" for s, n in counts.items()) + ".</p>"]
    top_assets = sorted(risks.items(), key=lambda kv: kv[1]["score"], reverse=True)[:5]
    h.append("<h2>Highest-risk assets</h2><table><tr><th>Asset</th><th>Criticality</th><th>Exposure</th><th>Risk</th></tr>")
    for aid, r in top_assets:
        a = assets[aid]
        h.append(f"<tr><td>{e(a.value)}</td><td>{a.criticality}/5</td><td>{e(a.exposure)}</td><td>{r['score']:.0f}</td></tr>")
    h.append("</table>")
    h.append("<h2>Top attack paths</h2>")
    if not paths:
        h.append("<p>No multi-step attack paths were identified.</p>")
    for p in paths[: (3 if kind == "executive" else 10)]:
        d = path_dict(db, p)
        h.append(f"<p><b>{e(d['entry'])} &rarr; {e(d['target'])}</b> ({d['hops']} hops, risk {d['risk_score']:.0f})<br>{e(d['explanation'])}</p>")
    lim = 5 if kind == "executive" else len(act)
    h.append("<h2>Priority findings</h2>" if kind == "executive" else "<h2>Findings</h2>")
    for f in act[:lim]:
        v = f.vulnerability
        h.append(f"<h3>{_sev(f.severity)} {e(f.title)} <span class='muted'>on {e(f.asset.value)}"
                 f"{':' + str(f.service.port) if f.service else ''} - risk {f.risk_score:.0f}, {e(f.status)}</span></h3>")
        if kind == "technical":
            h.append(f"<p>{e(v.description)}</p>")
            h.append("<table><tr><th>Risk factor</th><th>Points</th><th>Why</th></tr>" + "".join(
                f"<tr><td>{e(x['name'])}</td><td>{x['points']}</td><td>{e(x['reason'])}</td></tr>" for x in f.risk_factors or []) + "</table>")
            from .models import FindingEvidence
            for ev in db.query(FindingEvidence).filter_by(finding_id=f.id).order_by(FindingEvidence.id.desc()).limit(2):
                h.append(f"<pre>{e(ev.content)}</pre>")
        h.append(f"<p><b>Remediation:</b> {e(v.remediation)}</p>")
    if kind == "executive":
        h.append("<h2>Recommended next steps</h2><ol>" + "".join(
            f"<li>{e(f.vulnerability.remediation)} <span class='muted'>({e(f.asset.value)})</span></li>" for f in act[:3]) + "</ol>")
    h.append("</body></html>")
    return title, "".join(h)
