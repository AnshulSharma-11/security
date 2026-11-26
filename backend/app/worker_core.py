"""Job execution. Runs inside the isolated worker container (or inline in seed/tests)."""
import json
from .db import SessionLocal
from .models import Asset, Project, Scan, ScanJob, ScanResult, now
from .normalize import (apply_discovery, clean, nmap_findings, nuclei_finding, upsert_finding,
                        upsert_service, upsert_tech)
from .risk import recompute_project
from .scanners import ToolAborted, discover, run_nmap, run_nuclei
from .security import audit

DONE = ("completed", "failed", "cancelled")


def _finalize(db, scan: Scan):
    statuses = [s for (s,) in db.query(ScanJob.status).filter_by(scan_id=scan.id)]
    if any(s not in DONE for s in statuses):
        return
    db.refresh(scan)
    scan.status = ("cancelled" if scan.cancel_requested else "failed" if all(s == "failed" for s in statuses) else "completed")
    scan.finished_at = now()
    db.commit()
    org = db.get(Project, scan.project_id).org_id
    audit(db, None, f"scan.{scan.status}", project_id=scan.project_id, target_type="scan", target_id=scan.id, org_id=org,
          email="system:worker")


def process_job(job_id: int):
    db = SessionLocal()
    try:
        job = db.get(ScanJob, job_id)
        if not job or job.status != "queued":
            return
        scan, asset = db.get(Scan, job.scan_id), db.get(Asset, job.asset_id)

        def cancelled() -> bool:
            with SessionLocal() as s2:
                return bool(s2.query(Scan.cancel_requested).filter_by(id=scan.id).scalar())

        if scan.cancel_requested:
            job.status, job.finished_at = "cancelled", now()
            db.commit()
            return _finalize(db, scan)
        job.status, job.started_at = "running", now()
        if scan.status == "queued":
            scan.status, scan.started_at = "running", now()
        db.commit()
        raw, parsed, created, updated = "", 0, 0, 0
        try:
            # Authorization is re-verified at execution time, not only when the scan was requested.
            if asset.project_id != scan.project_id or asset.authorization_status != "approved":
                raise RuntimeError("Asset is not authorised for scanning")
            host = asset.hostname or asset.ip
            if job.tool == "discovery":
                res = discover(host, cancelled)
                apply_discovery(db, asset, res)
                raw, parsed = json.dumps(res)[:100000], len(res["services"])
            elif job.tool == "nmap":
                raw, services = run_nmap(host, cancelled)
                for d in services:
                    upsert_service(db, asset, d)
                    if d.get("product") and d.get("service") not in ("http", "https"):
                        upsert_tech(db, asset, d["product"], d.get("version"), "nmap")
                db.flush()
                found = nmap_findings(services)
                parsed = len(found)
                for nf in found:
                    _, new = upsert_finding(db, asset, nf)
                    created, updated = created + new, updated + (not new)
                asset.last_seen, asset.status = now(), ("active" if asset.status != "needs_review" else asset.status)
            elif job.tool == "nuclei":
                urls = [s.http_url for s in asset.services if s.http_url]
                if asset.asset_type == "url":
                    urls.append(asset.value)
                raw, items = run_nuclei(host, urls, cancelled)
                for it in items:
                    nf = nuclei_finding(it)
                    if nf:
                        parsed += 1
                        _, new = upsert_finding(db, asset, nf)
                        created, updated = created + new, updated + (not new)
            db.add(ScanResult(job_id=job.id, raw=clean(raw, 200000), parsed_count=parsed))
            job.status, job.findings_created, job.findings_updated = "completed", created, updated
        except ToolAborted:
            db.rollback()
            job = db.get(ScanJob, job_id)
            job.status, job.error = "cancelled", "Cancelled by user"
        except Exception as e:  # noqa: BLE001 - job failure must never crash the worker
            db.rollback()
            job = db.get(ScanJob, job_id)
            job.status, job.error = "failed", clean(e, 500)
        job.finished_at = now()
        db.commit()
        if job.status == "completed":
            recompute_project(db, scan.project_id)
        _finalize(db, db.get(Scan, scan.id))
    finally:
        db.close()
