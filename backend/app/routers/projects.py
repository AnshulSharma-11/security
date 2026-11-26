from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from ..config import settings
from ..db import get_db
from ..models import AuditLog, Project, ROLES, User
from ..security import admin_only, audit, current_user, hash_pw, project_for
from ..serializers import iso, ser_user
from .common import EMAIL_RE

router = APIRouter(tags=["projects & admin"])


class ProjectIn(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    description: str = Field("", max_length=1000)


class ProjectPatch(BaseModel):
    name: str | None = Field(None, min_length=2, max_length=120)
    description: str | None = Field(None, max_length=1000)


def _p(p):
    return {"id": p.id, "name": p.name, "description": p.description, "created_at": iso(p.created_at)}


@router.get("/projects")
def list_projects(user: User = Depends(current_user), db: Session = Depends(get_db)):
    return [_p(p) for p in db.query(Project).filter_by(org_id=user.org_id).order_by(Project.name)]


@router.post("/projects", status_code=201)
def create_project(body: ProjectIn, request: Request, user: User = Depends(admin_only), db: Session = Depends(get_db)):
    if db.query(Project).filter_by(org_id=user.org_id, name=body.name).first():
        raise HTTPException(409, "A project with that name already exists")
    p = Project(org_id=user.org_id, name=body.name, description=body.description)
    db.add(p); db.commit()
    audit(db, user, "project.create", project_id=p.id, target_type="project", target_id=p.id, request=request)
    return _p(p)


@router.get("/projects/{pid}")
def get_project(pid: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    return _p(project_for(db, user, pid))


@router.patch("/projects/{pid}")
def patch_project(pid: int, body: ProjectPatch, request: Request, user: User = Depends(admin_only), db: Session = Depends(get_db)):
    p = project_for(db, user, pid)
    for k, v in body.model_dump(exclude_none=True).items():
        setattr(p, k, v)
    db.commit()
    audit(db, user, "project.update", project_id=p.id, target_type="project", target_id=p.id, request=request)
    return _p(p)


# ----- users (any member can list colleagues for assignment; only admins manage them)
class UserIn(BaseModel):
    email: str = Field(pattern=EMAIL_RE, max_length=254)
    name: str = Field(min_length=1, max_length=120)
    password: str = Field(min_length=10, max_length=200)
    role: str = "analyst"


class UserPatch(BaseModel):
    role: str | None = None
    is_active: bool | None = None
    password: str | None = Field(None, min_length=10, max_length=200)


@router.get("/users")
def list_users(user: User = Depends(current_user), db: Session = Depends(get_db)):
    return [ser_user(u) for u in db.query(User).filter_by(org_id=user.org_id, is_active=True).order_by(User.name)]


@router.get("/admin/users")
def admin_users(user: User = Depends(admin_only), db: Session = Depends(get_db)):
    return [ser_user(u) for u in db.query(User).filter_by(org_id=user.org_id).order_by(User.name)]


@router.post("/admin/users", status_code=201)
def create_user(body: UserIn, request: Request, user: User = Depends(admin_only), db: Session = Depends(get_db)):
    if body.role not in ROLES:
        raise HTTPException(422, "Role must be admin or analyst")
    if db.query(User).filter_by(email=body.email.lower()).first():
        raise HTTPException(409, "That email is already registered")
    u = User(org_id=user.org_id, email=body.email.lower(), name=body.name, role=body.role, password_hash=hash_pw(body.password))
    db.add(u); db.commit()
    audit(db, user, "user.create", target_type="user", target_id=u.id, detail=f"{u.email} as {u.role}", request=request)
    return ser_user(u)


@router.patch("/admin/users/{uid}")
def patch_user(uid: int, body: UserPatch, request: Request, user: User = Depends(admin_only), db: Session = Depends(get_db)):
    u = db.get(User, uid)
    if not u or u.org_id != user.org_id:
        raise HTTPException(404, "User not found")
    if u.id == user.id and (body.is_active is False or (body.role and body.role != "admin")):
        raise HTTPException(400, "You cannot demote or disable your own account")
    if body.role:
        if body.role not in ROLES:
            raise HTTPException(422, "Role must be admin or analyst")
        u.role = body.role
    if body.is_active is not None:
        u.is_active = body.is_active
    if body.password:
        u.password_hash = hash_pw(body.password)
    db.commit()
    audit(db, user, "user.update", target_type="user", target_id=u.id,
          detail=f"role={u.role} active={u.is_active} password_changed={bool(body.password)}", request=request)
    return ser_user(u)


@router.get("/admin/audit-logs")
def audit_logs(limit: int = 100, project_id: int | None = None, action: str | None = None,
               user: User = Depends(admin_only), db: Session = Depends(get_db)):
    q = db.query(AuditLog).filter(AuditLog.org_id == user.org_id)
    if project_id:
        q = q.filter(AuditLog.project_id == project_id)
    if action:
        q = q.filter(AuditLog.action.like(f"{action}%"))
    return [{"id": a.id, "at": iso(a.created_at), "user": a.user_email, "action": a.action, "target_type": a.target_type,
             "target_id": a.target_id, "detail": a.detail, "ip": a.ip_address, "project_id": a.project_id}
            for a in q.order_by(AuditLog.id.desc()).limit(min(limit, 500))]


@router.get("/admin/integrations")
def integrations(user: User = Depends(admin_only)):
    from ..tasks import tool_status_task
    try:
        tools = tool_status_task.delay().get(timeout=4)
        worker = "online"
    except Exception:  # noqa: BLE001
        tools, worker = {"nmap": False, "nuclei": False}, "unreachable"
    return {"worker": worker, "queue": "redis" if not settings.eager else "inline (eager)",
            "tools": [{"name": "nmap", "purpose": "Service and version detection", "installed": tools.get("nmap", False)},
                      {"name": "nuclei", "purpose": "Template-based vulnerability checks (non-destructive tags only)", "installed": tools.get("nuclei", False)},
                      {"name": "discovery", "purpose": "DNS, TCP connect and HTTP probing (built in)", "installed": True}]}
