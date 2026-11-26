import time
from datetime import timedelta
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from ..config import settings
from ..db import get_db
from ..models import Project, User, now
from ..security import audit, current_user, decode_token, make_token, verify_pw
from ..serializers import ser_user
from .common import EMAIL_RE

router = APIRouter(prefix="/auth", tags=["auth"])
_fails: dict[str, list[float]] = {}  # in-memory brute-force throttle (per process; use Redis when scaling out)


class LoginIn(BaseModel):
    email: str = Field(pattern=EMAIL_RE, max_length=254)
    password: str = Field(min_length=1, max_length=200)


class RefreshIn(BaseModel):
    refresh_token: str


def _tokens(u: User):
    return {"access_token": make_token(u.id, "access", timedelta(minutes=settings.access_minutes)),
            "refresh_token": make_token(u.id, "refresh", timedelta(days=settings.refresh_days)), "token_type": "bearer"}


@router.post("/login")
def login(body: LoginIn, request: Request, db: Session = Depends(get_db)):
    key = body.email.lower()
    recent = [t for t in _fails.get(key, []) if time.time() - t < 900]
    if len(recent) >= 5:
        raise HTTPException(429, "Too many failed attempts. Try again in 15 minutes.")
    u = db.query(User).filter_by(email=key).first()
    if not (u and u.is_active and verify_pw(body.password, u.password_hash)):
        _fails[key] = recent + [time.time()]
        audit(db, None, "auth.login_failed", detail=key, request=request, org_id=u.org_id if u else None, email=key)
        raise HTTPException(401, "Incorrect email or password")
    _fails.pop(key, None)
    u.last_login = now()
    db.commit()
    audit(db, u, "auth.login", request=request)
    projects = db.query(Project).filter_by(org_id=u.org_id).order_by(Project.name).all()
    return {**_tokens(u), "user": ser_user(u),
            "projects": [{"id": p.id, "name": p.name, "description": p.description} for p in projects]}


@router.post("/refresh")
def refresh(body: RefreshIn, db: Session = Depends(get_db)):
    u = db.get(User, decode_token(body.refresh_token, "refresh"))
    if not u or not u.is_active:
        raise HTTPException(401, "Account disabled or not found")
    return _tokens(u)


@router.get("/me")
def me(user: User = Depends(current_user)):
    return ser_user(user)
