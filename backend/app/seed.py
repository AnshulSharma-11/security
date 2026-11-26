"""Demo data. Creates an organisation, two users and a project whose assets are SIMULATED lab targets
(*.lab.sentinel.local) -- nothing on the network is ever scanned. The data flows through the real
pipeline (discovery -> nmap/nuclei parsers -> dedup -> risk -> attack paths).

    python -m app.seed            # prints generated credentials once
"""
import os
import secrets
from datetime import timedelta
from .db import Base, SessionLocal, engine
from .models import (Asset, AssetLink, Finding, FindingStatusHistory, Organization, Project, RiskScore, Scan, ScanJob,
                     User, now)
from .normalize import clean
from .parsing_helpers import parse_target_simple
from .risk import recompute_project
from .security import hash_pw
from .worker_core import process_job

ASSETS = [  # value, criticality, exposure
    ("www.acme.lab.sentinel.local", 3, "internet"),
    ("portal.acme.lab.sentinel.local", 3, "internet"),
    ("app01.corp.lab.sentinel.local", 4, "internal"),
    ("db01.corp.lab.sentinel.local", 5, "internal"),
    ("files01.corp.lab.sentinel.local", 4, "internal"),
    ("dev01.corp.lab.sentinel.local", 2, "internal"),
]


def run_inline(db, project_id, asset_ids, tools, user_id):
    kind = "discovery" if tools == ["discovery"] else "assessment"
    scan = Scan(project_id=project_id, kind=kind, scanners=tools, created_by=user_id)
    for a in asset_ids:
        for t in tools:
            scan.jobs.append(ScanJob(asset_id=a, tool=t))
    db.add(scan); db.commit()
    for j in list(scan.jobs):
        process_job(j.id)
    db.expire_all()


def seed(db, password: str):
    if db.query(Organization).filter_by(name="Acme Corporation").first():
        return False
    org = Organization(name="Acme Corporation"); db.add(org); db.flush()
    admin = User(org_id=org.id, email="admin@sentinel.example", name="Alex Admin", role="admin", password_hash=hash_pw(password))
    analyst = User(org_id=org.id, email="analyst@sentinel.example", name="Ana Analyst", role="analyst", password_hash=hash_pw(password))
    proj = Project(org_id=org.id, name="Acme External Perimeter", description="Demo project built from simulated lab targets")
    db.add_all([admin, analyst, proj]); db.commit()
    ids = {}
    for value, crit, exp in ASSETS:
        a = Asset(project_id=proj.id, criticality=crit, exposure=exp, authorization_status="approved", authorized_by=admin.id,
                  authorized_at=now(), authorization_note="Simulated lab target (demo data)", created_by=admin.id,
                  **parse_target_simple(value))
        db.add(a); db.commit(); ids[value] = a.id
    all_ids = list(ids.values())
    run_inline(db, proj.id, all_ids, ["discovery"], admin.id)  # discovery fills IPs so subnets can be inferred
    for src, dst, rel, note in [("portal.acme.lab.sentinel.local", "app01.corp.lab.sentinel.local", "connects_to", "portal backend calls the app server API"),
                                ("www.acme.lab.sentinel.local", "app01.corp.lab.sentinel.local", "credential_reuse", "shared deploy credentials"),
                                ("app01.corp.lab.sentinel.local", "files01.corp.lab.sentinel.local", "trusts", "shared service account")]:
        db.add(AssetLink(project_id=proj.id, src_id=ids[src], dst_id=ids[dst], relation=rel, note=note, created_by=admin.id))
    db.commit()
    run_inline(db, proj.id, all_ids, ["nmap", "nuclei"], admin.id)
    f = db.query(Finding).filter(Finding.project_id == proj.id, Finding.title.like("Redis%")).first()
    if f:
        f.status, f.assignee_id = "in_progress", analyst.id
        db.add(FindingStatusHistory(finding_id=f.id, old_status="open", new_status="in_progress", user_id=analyst.id, note="Firewall change requested"))
    db.commit()
    recompute_project(db, proj.id)
    final = db.query(RiskScore).filter_by(project_id=proj.id).order_by(RiskScore.id.desc()).first().score
    for i, delta in enumerate([-11, -9, -12, -6, -4, -2], start=1):  # illustrative history for the trend chart
        db.add(RiskScore(project_id=proj.id, score=max(0, round(final + delta, 1)), detail={"demo": True},
                         created_at=now() - timedelta(days=7 - i)))
    db.commit()
    return True


if __name__ == "__main__":
    Base.metadata.create_all(engine)
    pw = os.environ.get("SENTINEL_DEMO_PASSWORD") or secrets.token_urlsafe(12)
    with SessionLocal() as db:
        if seed(db, pw):
            print(f"Demo data created.\n  admin   : admin@sentinel.example\n  analyst : analyst@sentinel.example\n  password: {pw}\n"
                  "(shown once; set SENTINEL_DEMO_PASSWORD to choose your own)")
        else:
            print("Demo data already present; nothing changed.")
