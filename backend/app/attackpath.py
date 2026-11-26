"""Attack-path intelligence. The graph is held in PostgreSQL tables (assets = nodes, links/inferred
adjacency = edges) and searched in Python: an acceptable stand-in for Neo4j at MVP scale.

Model: an attacker who controls asset A (A has an active finding of severity >= medium, a *foothold*) can
move to any asset B adjacent to A (explicit link or same /24). A path starts at an internet-exposed
foothold and ends at a high-value asset (criticality >= 4) that has at least one weakness."""
import ipaddress
from sqlalchemy.orm import Session
from .models import (Asset, AssetLink, AttackPath, AttackPathEdge, AttackPathNode, Finding, now)
from .risk import INACTIVE

MAX_HOPS = 4
MAX_PATHS = 25
FOOTHOLD = ("medium", "high", "critical")


def _info(db: Session, project_id: int):
    assets = {a.id: a for a in db.query(Asset).filter(Asset.project_id == project_id,
                                                        Asset.authorization_status != "revoked")}
    fs: dict[int, list[Finding]] = {}
    for f in db.query(Finding).filter_by(project_id=project_id):
        if f.status not in INACTIVE and f.asset_id in assets:
            fs.setdefault(f.asset_id, []).append(f)
    for v in fs.values():
        v.sort(key=lambda f: f.risk_score, reverse=True)
    return assets, fs


def _adjacency(db: Session, project_id: int, assets: dict[int, Asset]):
    adj: dict[int, dict[int, tuple[str, str]]] = {}
    for l in db.query(AssetLink).filter_by(project_id=project_id):
        if l.src_id in assets and l.dst_id in assets:
            adj.setdefault(l.src_id, {})[l.dst_id] = (
                l.relation, f"{l.relation.replace('_', ' ')}" + (f" ({l.note})" if l.note else ""))
    nets: dict[str, list[int]] = {}
    for a in assets.values():
        try:
            ip = ipaddress.ip_address(a.ip or "")
            if ip.version == 4:
                nets.setdefault(str(ipaddress.ip_network(f"{ip}/24", strict=False)), []).append(a.id)
        except ValueError:
            pass
    for net, ids in nets.items():
        for x in ids:
            for y in ids:
                if x != y and y not in adj.get(x, {}):
                    adj.setdefault(x, {})[y] = ("same_subnet",
                                                f"both sit in {net}, so a compromised host can attempt lateral movement")
    return adj


def analyze_paths(db: Session, project_id: int) -> int:
    assets, fs = _info(db, project_id)
    adj = _adjacency(db, project_id, assets)
    risk = {i: (fs[i][0].risk_score if i in fs else 0.0) for i in assets}
    foothold = {i for i, l in fs.items() if any(f.severity in FOOTHOLD for f in l)}
    entries = [i for i in foothold if assets[i].exposure == "internet"]
    targets = {i for i, a in assets.items() if a.criticality >= 4 and i in fs}
    best: dict[tuple[int, int], tuple[float, list, list, list]] = {}

    def record(nodes, edges):
        t = nodes[-1]
        avg = sum(risk[n] for n in nodes) / len(nodes)
        fac = [{"name": "Average weakness risk on path", "points": round(avg * 0.6, 1), "reason": f"mean finding risk {avg:.0f} x 0.6"},
               {"name": "Target criticality", "points": assets[t].criticality * 6, "reason": f"{assets[t].value} is criticality {assets[t].criticality}/5"},
               {"name": "Internet entry point", "points": 10, "reason": f"{assets[nodes[0]].value} is exposed to the internet"},
               {"name": "Hop penalty", "points": -3 * (len(edges) - 1), "reason": "Longer chains are harder to execute"}]
        score = round(min(100, max(0, sum(x["points"] for x in fac))), 1)
        key = (nodes[0], t)
        if key not in best or (score, -len(edges)) > (best[key][0], -len(best[key][2])):
            best[key] = (score, list(nodes), list(edges), fac)

    for e in entries:
        stack = [(e, [e], [])]
        while stack:
            cur, nodes, edges = stack.pop()
            if len(edges) >= MAX_HOPS:
                continue
            for nxt, (rel, why) in adj.get(cur, {}).items():
                if nxt in nodes:
                    continue
                n2, e2 = nodes + [nxt], edges + [(cur, nxt, rel, why)]
                if nxt in targets:
                    record(n2, e2)
                if nxt in foothold:
                    stack.append((nxt, n2, e2))
    for p in db.query(AttackPath).filter_by(project_id=project_id).all():
        db.delete(p)
    db.flush()
    ranked = sorted(best.values(), key=lambda x: x[0], reverse=True)[:MAX_PATHS]
    for score, nodes, edges, fac in ranked:
        steps = [f"Entry: {assets[nodes[0]].value} is internet-facing and exposes '{fs[nodes[0]][0].title}' (risk {fs[nodes[0]][0].risk_score:.0f})."]
        for a, b, rel, why in edges:
            steps.append(f"From {assets[a].value} the attacker reaches {assets[b].value} via {why}; "
                         f"it has '{fs[b][0].title}' (risk {fs[b][0].risk_score:.0f}).")
        t = assets[nodes[-1]]
        steps.append(f"Target: {t.value} is criticality {t.criticality}/5, so compromise here has high business impact.")
        p = AttackPath(project_id=project_id, entry_asset_id=nodes[0], target_asset_id=nodes[-1], hops=len(edges),
                       risk_score=score, score_factors=fac, explanation=" ".join(steps), created_at=now())
        for i, n in enumerate(nodes):
            p.nodes.append(AttackPathNode(position=i, asset_id=n, role="entry" if i == 0 else "target" if i == len(nodes) - 1 else "pivot"))
        for i, (a, b, rel, why) in enumerate(edges):
            foot = next((f for f in fs[a] if f.severity in FOOTHOLD), fs[a][0])
            p.edges.append(AttackPathEdge(position=i, from_asset_id=a, to_asset_id=b, relation=rel, reason=why[:500], finding_id=foot.id))
        db.add(p)
    return len(ranked)


def path_asset_ids(db: Session, project_id: int) -> set[int]:
    ids: set[int] = set()
    for p in db.query(AttackPath).filter_by(project_id=project_id):
        ids.update(n.asset_id for n in p.nodes)
    return ids


def path_dict(db: Session, p: AttackPath, detail: bool = False) -> dict:
    d = {"id": p.id, "project_id": p.project_id, "hops": p.hops, "risk_score": p.risk_score,
         "entry": next(n.asset.value for n in p.nodes if n.role == "entry"),
         "target": next(n.asset.value for n in p.nodes if n.role == "target"),
         "explanation": p.explanation}
    if detail:
        fs = {f.id: f for f in db.query(Finding).filter(Finding.id.in_([e.finding_id for e in p.edges if e.finding_id]))}
        top = {}
        for f in db.query(Finding).filter(Finding.project_id == p.project_id,
                                          Finding.asset_id.in_([n.asset_id for n in p.nodes])):
            if f.status not in INACTIVE and (f.asset_id not in top or f.risk_score > top[f.asset_id].risk_score):
                top[f.asset_id] = f
        d["score_factors"] = p.score_factors
        d["nodes"] = [{"position": n.position, "role": n.role, "asset_id": n.asset_id, "value": n.asset.value,
                       "exposure": n.asset.exposure, "criticality": n.asset.criticality,
                       "top_finding": ({"id": top[n.asset_id].id, "title": top[n.asset_id].title,
                                        "severity": top[n.asset_id].severity, "risk_score": top[n.asset_id].risk_score}
                                       if n.asset_id in top else None)} for n in p.nodes]
        d["edges"] = [{"position": e.position, "from": e.from_asset_id, "to": e.to_asset_id, "relation": e.relation,
                       "reason": e.reason, "finding": (fs[e.finding_id].title if e.finding_id in fs else None)} for e in p.edges]
    return d
