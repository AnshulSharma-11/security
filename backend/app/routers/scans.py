from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from ..db import get_db
from ..models import Asset, Scan, ScanJob, User, now
from ..security import audit, current_user, project_for
from ..serializers import ser_scan
from ..tasks import celery_app, run_job

router = APIRouter(prefix="/scans", tags=["scans"])
discovery_router = APIRouter(prefix="/discovery", tags=["discovery"])
TOOLS = ("nmap", "nuclei")


class ScanIn(BaseModel):
    project_id: int
    asset_ids: list[int] = Field(min_length=1, max_length=50)
    scanners: list[str] = Field(default_factory=lambda: list(TOOLS), min_length=1)


class DiscoveryIn(BaseModel):
    project_id: int
    asset_ids: list[int] = Field(min_length=1, max_length=50)


def _names(db: Session, scan: Scan):
    return {a.id: a.value for a in db.query(Asset).filter(Asset.id.in_([j.asset_id for j in scan.jobs]))}


def _scan_for(db: Session, user: User, sid: int) -> Scan:
    s = db.get(Scan, sid)
    if not s:
        raise HTTPException(404, "Scan not found")
    project_for(db, user, s.project_id)
    return s


def _create(db, user, request, project_id, asset_ids, tools, kind) -> dict:
    project = project_for(db, user, project_id)
    ids = set(asset_ids)
    assets = db.query(Asset).filter(Asset.id.in_(ids), Asset.project_id == project.id).all()
    if len(assets) != len(ids):
        raise HTTPException(404, "One or more assets were not found in this project")
    blocked = [a.value for a in assets if a.authorization_status != "approved"]
    if blocked:  # hard authorisation gate: never queue work for an unapproved asset
        raise HTTPException(403, "Scanning requires administrator-approved authorisation for: " + ", ".join(blocked))
    scan = Scan(project_id=project.id, kind=kind, scanners=list(tools), created_by=user.id)
    for a in assets:
        for t in tools:
            scan.jobs.append(ScanJob(asset_id=a.id, tool=t))
    db.add(scan); db.commit()
    audit(db, user, f"{kind}.start", project_id=project.id, target_type="scan", target_id=scan.id,
          detail=f"tools={','.join(tools)} assets={','.join(a.value for a in assets)}", request=request)
    try:
        sent = []
        for j in [(j.id) for j in scan.jobs]:
            r = run_job.delay(j)  # the API only enqueues; execution happens in the worker container
            sent.append((j, getattr(r, "id", None)))
        for jid, tid in sent:  # record task ids after enqueueing (keeps API transactions short)
            db.query(ScanJob).filter_by(id=jid, status="queued").update({"celery_id": tid})
        db.commit()
    except Exception as e:  # noqa: BLE001 - broker down
        db.rollback()
        s = db.get(Scan, scan.id)
        s.status, s.finished_at = "failed", now()
        for j in s.jobs:
            j.status, j.error = "failed", "Job queue unavailable"
        db.commit()
    db.expire_all()
    s = db.get(Scan, scan.id)
    return ser_scan(s, _names(db, s))


@router.post("", status_code=202)
def create_scan(body: ScanIn, request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    if any(t not in TOOLS for t in body.scanners):
        raise HTTPException(422, f"Scanners must be among {TOOLS}")
    return _create(db, user, request, body.project_id, body.asset_ids, sorted(set(body.scanners)), "assessment")


@router.get("")
def list_scans(project_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    project_for(db, user, project_id)
    return [ser_scan(s, _names(db, s)) for s in db.query(Scan).filter_by(project_id=project_id).order_by(Scan.id.desc()).limit(50)]


@router.get("/{sid}")
def get_scan(sid: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    s = _scan_for(db, user, sid)
    return ser_scan(s, _names(db, s))


@router.post("/{sid}/cancel")
def cancel_scan(sid: int, request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    s = _scan_for(db, user, sid)
    if s.status in ("completed", "failed", "cancelled"):
        raise HTTPException(409, f"Scan already {s.status}")
    s.cancel_requested = True
    ids = [j.celery_id for j in s.jobs if j.status == "queued" and j.celery_id]
    for j in s.jobs:
        if j.status == "queued":
            j.status, j.error, j.finished_at = "cancelled", "Cancelled by user", now()
    if not any(j.status == "running" for j in s.jobs):
        s.status, s.finished_at = "cancelled", now()
    db.commit()
    try:
        if ids:
            celery_app.control.revoke(ids)
    except Exception:  # noqa: BLE001
        pass  # the worker also checks cancel_requested before starting each job
    audit(db, user, "scan.cancel", project_id=s.project_id, target_type="scan", target_id=s.id, request=request)
    return ser_scan(s, _names(db, s))


@discovery_router.post("", status_code=202)
def start_discovery(body: DiscoveryIn, request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    return _create(db, user, request, body.project_id, body.asset_ids, ["discovery"], "discovery")


@discovery_router.get("/{sid}")
def get_discovery(sid: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    s = _scan_for(db, user, sid)
    if s.kind != "discovery":
        raise HTTPException(404, "Discovery run not found")
    return ser_scan(s, _names(db, s))
