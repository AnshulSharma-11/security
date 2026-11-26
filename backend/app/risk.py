"""Transparent risk engine. Every finding score is the sum of named, capped factors (max 100) that are
stored with the finding and shown in the UI, so an analyst can always see *why* it scored what it did."""
from datetime import timezone
from sqlalchemy.orm import Session
from .models import Asset, AttackPath, Finding, RiskScore, now

SEV_PTS = {"critical": 35, "high": 26, "medium": 16, "low": 8, "info": 2}
INACTIVE = ("false_positive", "resolved")
EXPLOIT_TAGS = {"kev", "rce", "exploit", "unauth", "default-login"}


def level(score: float) -> str:
    return "critical" if score >= 75 else "high" if score >= 55 else "medium" if score >= 35 else "low"


def score_finding(f: Finding, a: Asset, on_path: bool) -> tuple[float, list[dict]]:
    v = f.vulnerability
    F = []

    def add(name, pts, mx, why):
        F.append({"name": name, "points": pts, "max": mx, "reason": why})

    add("Severity", SEV_PTS[f.severity], 35, f"Scanner rated this {f.severity}")
    cv = round(v.cvss) if v.cvss else 0
    add("CVSS", cv, 10, f"CVSS {v.cvss}" if v.cvss else "No CVSS reported")
    ex = {"internet": (20, "Asset is reachable from the internet"),
          "internal": (4, "Asset is only reachable from the internal network"),
          }.get(a.exposure, (8, "Exposure not yet determined, scored as partially exposed"))
    add("Internet exposure", ex[0], 20, ex[1])
    add("Asset criticality", a.criticality * 4, 20, f"Asset criticality {a.criticality}/5")
    tags = set(v.tags or [])
    xp = min(10, (5 if v.cve else 0) + (5 if (tags & EXPLOIT_TAGS) else 0))
    add("Known exploitability", xp, 10, "Has a CVE and/or exploit-related tags" if xp else "No known public exploit indicators")
    add("Attack-path involvement", 5 if on_path else 0, 5,
        "Asset is part of an identified attack path" if on_path else "Asset is not on any attack path")
    total = sum(x["points"] for x in F)
    if f.status in INACTIVE:
        F.append({"name": "Status", "points": -total, "max": 0, "reason": f"Marked {f.status.replace('_', ' ')}: not counted"})
        total = 0
    elif f.status == "accepted_risk":
        cut = round(total * 0.6)
        F.append({"name": "Status", "points": -cut, "max": 0, "reason": "Accepted risk: reduced by 60%"})
        total -= cut
    return float(min(100, max(0, total))), F


def _score_all(db: Session, project_id: int, on_path: set[int]):
    for f in db.query(Finding).filter_by(project_id=project_id).all():
        f.risk_score, f.risk_factors = score_finding(f, f.asset, f.asset_id in on_path)


def active_findings(db: Session, project_id: int) -> list[Finding]:
    return [f for f in db.query(Finding).filter_by(project_id=project_id).all() if f.status not in INACTIVE]


def asset_risks(db: Session, project_id: int) -> dict[int, dict]:
    out: dict[int, dict] = {}
    for f in active_findings(db, project_id):
        d = out.setdefault(f.asset_id, {"score": 0, "counts": {}})
        d["score"] = max(d["score"], f.risk_score)
        d["counts"][f.severity] = d["counts"].get(f.severity, 0) + 1
    return out


def project_score(db: Session, project_id: int) -> float:
    top = sorted((f.risk_score for f in active_findings(db, project_id)), reverse=True)[:5]
    if not top:
        return 0.0
    avg = sum(top) / len(top)
    best = db.query(AttackPath).filter_by(project_id=project_id).order_by(AttackPath.risk_score.desc()).first()
    return round(avg * 0.7 + best.risk_score * 0.3, 1) if best else round(avg, 1)


def snapshot(db: Session, project_id: int):
    act = active_findings(db, project_id)
    detail = {"critical": sum(f.severity == "critical" for f in act), "high": sum(f.severity == "high" for f in act),
              "open_findings": len(act)}
    score = project_score(db, project_id)
    last = db.query(RiskScore).filter_by(project_id=project_id).order_by(RiskScore.id.desc()).first()
    if last and last.created_at:
        t = last.created_at if last.created_at.tzinfo else last.created_at.replace(tzinfo=timezone.utc)
        if (now() - t).total_seconds() < 60:
            last.score, last.detail = score, detail
            return
    db.add(RiskScore(project_id=project_id, score=score, detail=detail))


def recompute_project(db: Session, project_id: int, analyze: bool = True):
    """Score findings -> rebuild attack paths -> rescore (path bonus) -> snapshot."""
    from .attackpath import analyze_paths, path_asset_ids
    _score_all(db, project_id, path_asset_ids(db, project_id))
    db.flush()
    if analyze:
        analyze_paths(db, project_id)
        db.flush()
        _score_all(db, project_id, path_asset_ids(db, project_id))
    db.flush()
    snapshot(db, project_id)
    db.commit()
