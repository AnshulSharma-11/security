from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from ..attackpath import path_dict
from ..db import get_db
from ..models import Asset, AttackPath, Finding, RiskScore, User
from ..risk import active_findings, asset_risks, level, project_score
from ..security import current_user, project_for
from ..serializers import iso, ser_finding

router = APIRouter(prefix="/risk", tags=["risk"])


@router.get("/overview")
def overview(project_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    project_for(db, user, project_id)
    act = active_findings(db, project_id)
    assets = db.query(Asset).filter_by(project_id=project_id).all()
    by_day: dict[str, float] = {}
    for r in db.query(RiskScore).filter_by(project_id=project_id).order_by(RiskScore.id):
        by_day[iso(r.created_at)[:10]] = r.score
    paths = db.query(AttackPath).filter_by(project_id=project_id).order_by(AttackPath.risk_score.desc()).limit(3).all()
    sc = project_score(db, project_id)
    return {"risk_score": sc, "level": level(sc), "total_assets": len(assets),
            "assets_by_status": {s: sum(a.status == s for a in assets) for s in ("active", "inactive", "needs_review")},
            "pending_authorization": sum(a.authorization_status == "pending" for a in assets),
            "severity_counts": {s: sum(f.severity == s for f in act) for s in ("critical", "high", "medium", "low", "info")},
            "active_findings": len(act), "critical_high": sum(f.severity in ("critical", "high") for f in act),
            "trend": [{"date": d, "score": s} for d, s in list(by_day.items())[-30:]],
            "top_paths": [path_dict(db, p) for p in paths]}


@router.get("/top")
def top(project_id: int, limit: int = 10, user: User = Depends(current_user), db: Session = Depends(get_db)):
    project_for(db, user, project_id)
    risks = asset_risks(db, project_id)
    assets = {a.id: a for a in db.query(Asset).filter_by(project_id=project_id)}
    ranked = sorted(risks.items(), key=lambda kv: kv[1]["score"], reverse=True)[: min(limit, 50)]
    fs = sorted(active_findings(db, project_id), key=lambda f: f.risk_score, reverse=True)[: min(limit, 50)]
    return {"assets": [{"id": i, "value": assets[i].value, "criticality": assets[i].criticality, "exposure": assets[i].exposure,
                        "risk_score": r["score"], "counts": r["counts"]} for i, r in ranked],
            "findings": [ser_finding(f) for f in fs]}
