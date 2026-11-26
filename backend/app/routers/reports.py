from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from ..db import get_db
from ..models import Report, User
from ..reportgen import build
from ..security import audit, current_user, project_for
from ..serializers import iso

router = APIRouter(prefix="/reports", tags=["reports"])


class ReportIn(BaseModel):
    project_id: int
    kind: str = Field(pattern="^(executive|technical)$")


def _meta(r: Report, content=False):
    d = {"id": r.id, "project_id": r.project_id, "kind": r.kind, "title": r.title, "created_at": iso(r.created_at)}
    if content:
        d["content"] = r.content
    return d


def _get(db, user, rid) -> Report:
    r = db.get(Report, rid)
    if not r:
        raise HTTPException(404, "Report not found")
    project_for(db, user, r.project_id)
    return r


@router.post("", status_code=201)
def create_report(body: ReportIn, request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    p = project_for(db, user, body.project_id)
    title, content = build(db, p, body.kind)
    r = Report(project_id=p.id, kind=body.kind, title=title, content=content, created_by=user.id)
    db.add(r); db.commit()
    audit(db, user, "report.create", project_id=p.id, target_type="report", target_id=r.id, detail=body.kind, request=request)
    return _meta(r)


@router.get("")
def list_reports(project_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    project_for(db, user, project_id)
    return [_meta(r) for r in db.query(Report).filter_by(project_id=project_id).order_by(Report.id.desc()).limit(50)]


@router.get("/{rid}")
def get_report(rid: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    return _meta(_get(db, user, rid), content=True)


@router.get("/{rid}/download")
def download(rid: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    r = _get(db, user, rid)
    return HTMLResponse(r.content, headers={"Content-Disposition": f'attachment; filename="sentinel-report-{r.id}.html"',
                                            "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'"})
