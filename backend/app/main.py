from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from .config import settings
from .db import Base, SessionLocal, engine
from .models import Organization, User
from .routers import assets, attack_paths, auth, findings, projects, reports, risk, scans
from .security import hash_pw


@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(engine)  # production deployments should use the SQL in docs/schema.sql / migrations
    if settings.bootstrap_admin_email and settings.bootstrap_admin_password:
        with SessionLocal() as db:
            if not db.query(User).count():
                org = Organization(name="Default Organization")
                db.add(org); db.flush()
                db.add(User(org_id=org.id, email=settings.bootstrap_admin_email.lower(), name="Administrator", role="admin",
                            password_hash=hash_pw(settings.bootstrap_admin_password)))
                db.commit()
    yield


app = FastAPI(title="Nexavise Sentinel API", version="1.0.0", lifespan=lifespan,
              description="Attack-surface discovery, vulnerability management, risk prioritisation and attack-path intelligence.")
app.add_middleware(CORSMiddleware, allow_origins=[o.strip() for o in settings.cors_origins.split(",") if o.strip()],
                   allow_methods=["*"], allow_headers=["Authorization", "Content-Type"])


@app.middleware("http")
async def security_headers(request, call_next):
    r = await call_next(request)
    r.headers.setdefault("X-Content-Type-Options", "nosniff")
    r.headers.setdefault("X-Frame-Options", "DENY")
    r.headers.setdefault("Referrer-Policy", "no-referrer")
    r.headers.setdefault("Cache-Control", "no-store")
    return r


for m in (auth, projects, assets, findings, risk, attack_paths, reports):
    app.include_router(m.router)
app.include_router(scans.router)
app.include_router(scans.discovery_router)


@app.get("/health", tags=["meta"])
def health():
    return {"status": "ok"}
