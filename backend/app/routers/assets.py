from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from ..db import get_db
from ..models import Asset, AssetLink, Finding, Technology, User, now
from ..risk import asset_risks, recompute_project
from ..security import admin_only, audit, current_user, project_for
from ..serializers import ser_asset, ser_finding
from .common import parse_target

router = APIRouter(prefix="/assets", tags=["assets"])
EXPOSURE = ("internet", "internal", "unknown")


class AssetIn(BaseModel):
    project_id: int
    value: str = Field(max_length=300)
    criticality: int = Field(3, ge=1, le=5)
    exposure: str = "unknown"
    authorization_note: str = Field("", max_length=500)
    confirm_authorized: bool = False


class AssetPatch(BaseModel):
    criticality: int | None = Field(None, ge=1, le=5)
    exposure: str | None = None
    status: str | None = None
    authorization_status: str | None = None
    authorization_note: str | None = Field(None, max_length=500)


class LinkIn(BaseModel):
    target_asset_id: int
    relation: str = Field("connects_to", pattern="^(connects_to|trusts|credential_reuse|network_adjacent|hosts)$")
    note: str = Field("", max_length=300)


def asset_for(db: Session, user: User, aid: int) -> Asset:
    a = db.get(Asset, aid)
    if not a:
        raise HTTPException(404, "Asset not found")
    project_for(db, user, a.project_id)  # tenant check
    return a


@router.get("")
def list_assets(project_id: int, q: str | None = None, type: str | None = None, exposure: str | None = None,
                status: str | None = None, technology: str | None = None, authorization: str | None = None,
                user: User = Depends(current_user), db: Session = Depends(get_db)):
    project_for(db, user, project_id)
    qs = db.query(Asset).filter(Asset.project_id == project_id)
    if q:
        qs = qs.filter(Asset.value.ilike(f"%{q[:100]}%"))
    if type:
        qs = qs.filter(Asset.asset_type == type)
    if exposure:
        qs = qs.filter(Asset.exposure == exposure)
    if status:
        qs = qs.filter(Asset.status == status)
    if authorization:
        qs = qs.filter(Asset.authorization_status == authorization)
    if technology:
        qs = qs.filter(Asset.id.in_(db.query(Technology.asset_id).filter(Technology.name.ilike(f"%{technology[:60]}%"))))
    risks = asset_risks(db, project_id)
    return [ser_asset(a, risks.get(a.id, {}).get("score"), risks.get(a.id, {}).get("counts"))
            for a in qs.order_by(Asset.value)]


@router.post("", status_code=201)
def create_asset(body: AssetIn, request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    project_for(db, user, body.project_id)
    if not body.confirm_authorized:
        raise HTTPException(422, "Confirm that you are authorised to assess this asset")
    if body.exposure not in EXPOSURE:
        raise HTTPException(422, "Exposure must be internet, internal or unknown")
    t = parse_target(body.value)
    if db.query(Asset).filter_by(project_id=body.project_id, value=t["value"]).first():
        raise HTTPException(409, "This asset is already in the project")
    approved = user.role == "admin"  # analysts' assets wait for admin approval before any scan can run
    a = Asset(project_id=body.project_id, criticality=body.criticality, exposure=body.exposure, created_by=user.id,
              authorization_note=body.authorization_note, authorization_status="approved" if approved else "pending",
              authorized_by=user.id if approved else None, authorized_at=now() if approved else None, **t)
    db.add(a); db.commit()
    audit(db, user, "asset.create", project_id=a.project_id, target_type="asset", target_id=a.id,
          detail=f"{a.value} authorization={a.authorization_status}", request=request)
    return ser_asset(a)


@router.get("/{aid}")
def get_asset(aid: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    a = asset_for(db, user, aid)
    d = ser_asset(a, **{k: v for k, v in zip(("risk", "counts"), (lambda r: (r.get("score"), r.get("counts")))(asset_risks(db, a.project_id).get(a.id, {})))})
    d["findings"] = [ser_finding(f) for f in db.query(Finding).filter_by(asset_id=a.id).order_by(Finding.risk_score.desc())]
    names = {x.id: x.value for x in db.query(Asset).filter_by(project_id=a.project_id)}
    d["links"] = [{"id": l.id, "src": l.src_id, "dst": l.dst_id, "src_value": names.get(l.src_id), "dst_value": names.get(l.dst_id),
                   "relation": l.relation, "note": l.note}
                  for l in db.query(AssetLink).filter((AssetLink.src_id == a.id) | (AssetLink.dst_id == a.id))]
    return d


@router.patch("/{aid}")
def patch_asset(aid: int, body: AssetPatch, request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    a = asset_for(db, user, aid)
    ch = body.model_dump(exclude_none=True)
    if "authorization_status" in ch:
        if user.role != "admin":
            raise HTTPException(403, "Only administrators can approve or revoke scan authorisation")
        if ch["authorization_status"] not in ("pending", "approved", "revoked"):
            raise HTTPException(422, "Invalid authorisation status")
        a.authorized_by, a.authorized_at = user.id, now()
    if "exposure" in ch and ch["exposure"] not in EXPOSURE:
        raise HTTPException(422, "Invalid exposure")
    if "status" in ch and ch["status"] not in ("active", "inactive", "needs_review"):
        raise HTTPException(422, "Invalid status")
    for k, v in ch.items():
        setattr(a, k, v)
    db.commit()
    audit(db, user, "asset.update", project_id=a.project_id, target_type="asset", target_id=a.id, detail=str(ch), request=request)
    if {"criticality", "exposure", "authorization_status"} & ch.keys():
        recompute_project(db, a.project_id)
    return ser_asset(a)


@router.post("/{aid}/links", status_code=201)
def add_link(aid: int, body: LinkIn, request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    a = asset_for(db, user, aid)
    b = asset_for(db, user, body.target_asset_id)
    if a.project_id != b.project_id or a.id == b.id:
        raise HTTPException(422, "Link two different assets of the same project")
    if db.query(AssetLink).filter_by(src_id=a.id, dst_id=b.id, relation=body.relation).first():
        raise HTTPException(409, "Link already exists")
    l = AssetLink(project_id=a.project_id, src_id=a.id, dst_id=b.id, relation=body.relation, note=body.note, created_by=user.id)
    db.add(l); db.commit()
    audit(db, user, "asset.link", project_id=a.project_id, target_type="asset", target_id=a.id,
          detail=f"{a.value} -[{l.relation}]-> {b.value}", request=request)
    recompute_project(db, a.project_id)
    return {"id": l.id}


@router.delete("/{aid}/links/{lid}", status_code=204)
def del_link(aid: int, lid: int, request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    a = asset_for(db, user, aid)
    l = db.get(AssetLink, lid)
    if not l or l.project_id != a.project_id or aid not in (l.src_id, l.dst_id):
        raise HTTPException(404, "Link not found")
    db.delete(l); db.commit()
    audit(db, user, "asset.unlink", project_id=a.project_id, target_type="asset", target_id=a.id, request=request)
    recompute_project(db, a.project_id)
