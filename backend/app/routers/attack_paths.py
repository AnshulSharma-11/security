from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session
from ..attackpath import path_dict
from ..db import get_db
from ..models import AttackPath, User
from ..risk import recompute_project
from ..security import audit, current_user, project_for

router = APIRouter(prefix="/attack-paths", tags=["attack paths"])


class AnalyzeIn(BaseModel):
    project_id: int


@router.get("")
def list_paths(project_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    project_for(db, user, project_id)
    return [path_dict(db, p) for p in db.query(AttackPath).filter_by(project_id=project_id).order_by(AttackPath.risk_score.desc())]


@router.post("/analyze")
def analyze(body: AnalyzeIn, request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    project_for(db, user, body.project_id)
    recompute_project(db, body.project_id)
    n = db.query(AttackPath).filter_by(project_id=body.project_id).count()
    audit(db, user, "attackpath.analyze", project_id=body.project_id, detail=f"{n} paths", request=request)
    return {"paths": n}


@router.get("/{pid}")
def get_path(pid: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    p = db.get(AttackPath, pid)
    if not p:
        raise HTTPException(404, "Attack path not found")
    project_for(db, user, p.project_id)
    return path_dict(db, p, detail=True)
