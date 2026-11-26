from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from ..db import get_db
from ..models import Asset, Finding, FindingEvidence, FindingStatusHistory, SEVERITIES, STATUSES, User
from ..risk import recompute_project
from ..security import audit, current_user, project_for
from ..serializers import iso, ser_finding

router = APIRouter(prefix="/findings", tags=["findings"])


class FindingPatch(BaseModel):
    status: str
    note: str = Field("", max_length=500)


class AssignIn(BaseModel):
    user_id: int | None = None


def finding_for(db, user, fid) -> Finding:
    f = db.get(Finding, fid)
    if not f:
        raise HTTPException(404, "Finding not found")
    project_for(db, user, f.project_id)
    return f


@router.get("")
def list_findings(project_id: int, severity: str | None = None, status: str | None = None, asset_id: int | None = None,
                  assignee_id: int | None = None, q: str | None = None, sort: str = "risk", limit: int = 50, offset: int = 0,
                  user: User = Depends(current_user), db: Session = Depends(get_db)):
    project_for(db, user, project_id)
    qs = db.query(Finding).filter(Finding.project_id == project_id)
    if severity:
        qs = qs.filter(Finding.severity.in_([s for s in severity.split(",") if s in SEVERITIES]))
    if status:
        qs = qs.filter(Finding.status.in_([s for s in status.split(",") if s in STATUSES]))
    if asset_id:
        qs = qs.filter(Finding.asset_id == asset_id)
    if assignee_id:
        qs = qs.filter(Finding.assignee_id == assignee_id)
    if q:
        qs = qs.join(Asset, Asset.id == Finding.asset_id).filter(
            Finding.title.ilike(f"%{q[:100]}%") | Asset.value.ilike(f"%{q[:100]}%"))
    total = qs.count()
    order = Finding.last_seen.desc() if sort == "last_seen" else Finding.risk_score.desc()
    items = qs.order_by(order, Finding.id).offset(max(offset, 0)).limit(min(limit, 200)).all()
    return {"total": total, "items": [ser_finding(f) for f in items]}


@router.get("/{fid}")
def get_finding(fid: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    f = finding_for(db, user, fid)
    d = ser_finding(f, detail=True)
    d["evidence"] = [{"id": e.id, "tool": e.tool, "content": e.content, "at": iso(e.created_at)}
                     for e in db.query(FindingEvidence).filter_by(finding_id=f.id).order_by(FindingEvidence.id.desc())]
    names = {u.id: u.name for u in db.query(User).filter_by(org_id=user.org_id)}
    d["history"] = [{"old": h.old_status, "new": h.new_status, "by": names.get(h.user_id, "System"), "note": h.note,
                     "at": iso(h.created_at)}
                    for h in db.query(FindingStatusHistory).filter_by(finding_id=f.id).order_by(FindingStatusHistory.id.desc())]
    return d


@router.patch("/{fid}")
def patch_finding(fid: int, body: FindingPatch, request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    f = finding_for(db, user, fid)
    if body.status not in STATUSES:
        raise HTTPException(422, f"Status must be one of {STATUSES}")
    if body.status == "accepted_risk" and user.role != "admin":
        raise HTTPException(403, "Only administrators can accept risk")
    if body.status != f.status:
        db.add(FindingStatusHistory(finding_id=f.id, old_status=f.status, new_status=body.status, user_id=user.id, note=body.note))
        old, f.status = f.status, body.status
        db.commit()
        audit(db, user, "finding.status", project_id=f.project_id, target_type="finding", target_id=f.id,
              detail=f"{old} -> {body.status}", request=request)
        recompute_project(db, f.project_id)
    return ser_finding(finding_for(db, user, fid), detail=True)


@router.post("/{fid}/assign")
def assign(fid: int, body: AssignIn, request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    f = finding_for(db, user, fid)
    if body.user_id is not None:
        u = db.get(User, body.user_id)
        if not u or u.org_id != user.org_id or not u.is_active:
            raise HTTPException(404, "User not found")
    f.assignee_id = body.user_id
    db.commit()
    audit(db, user, "finding.assign", project_id=f.project_id, target_type="finding", target_id=f.id,
          detail=f"assignee={body.user_id}", request=request)
    db.expire_all()
    return ser_finding(db.get(Finding, fid), detail=True)
