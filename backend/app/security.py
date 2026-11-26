from datetime import datetime, timedelta, timezone
import bcrypt
import jwt
from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session
from .config import settings
from .db import get_db
from .models import AuditLog, Project, User

bearer = HTTPBearer(auto_error=False)


def hash_pw(p: str) -> str:
    return bcrypt.hashpw(p.encode()[:72], bcrypt.gensalt()).decode()


def verify_pw(p: str, h: str) -> bool:
    try:
        return bcrypt.checkpw(p.encode()[:72], h.encode())
    except ValueError:
        return False


def make_token(user_id: int, typ: str, delta: timedelta) -> str:
    n = datetime.now(timezone.utc)
    return jwt.encode({"sub": str(user_id), "typ": typ, "iat": n, "exp": n + delta},
                      settings.secret_key, algorithm="HS256")


def decode_token(token: str, typ: str) -> int:
    try:
        d = jwt.decode(token, settings.secret_key, algorithms=["HS256"])
        if d.get("typ") != typ:
            raise jwt.InvalidTokenError("wrong token type")
        return int(d["sub"])
    except (jwt.PyJWTError, ValueError, KeyError):
        raise HTTPException(401, "Invalid or expired token")


def current_user(creds: HTTPAuthorizationCredentials | None = Depends(bearer),
                 db: Session = Depends(get_db)) -> User:
    if not creds:
        raise HTTPException(401, "Not authenticated")
    user = db.get(User, decode_token(creds.credentials, "access"))
    if not user or not user.is_active:
        raise HTTPException(401, "Account disabled or not found")
    return user


def admin_only(user: User = Depends(current_user)) -> User:
    if user.role != "admin":
        raise HTTPException(403, "Administrator role required")
    return user


def project_for(db: Session, user: User, project_id: int) -> Project:
    """Tenant isolation: a project outside the caller's organisation looks like it does not exist."""
    p = db.get(Project, project_id)
    if not p or p.org_id != user.org_id:
        raise HTTPException(404, "Project not found")
    return p


def audit(db: Session, user: User | None, action: str, *, project_id=None, target_type=None,
          target_id=None, detail="", request: Request | None = None, org_id=None, email=None):
    db.add(AuditLog(org_id=user.org_id if user else org_id, project_id=project_id,
                    user_id=user.id if user else None, user_email=user.email if user else email,
                    action=action, target_type=target_type, target_id=target_id,
                    detail=str(detail)[:1000],
                    ip_address=(request.client.host if request and request.client else None)))
    db.commit()
