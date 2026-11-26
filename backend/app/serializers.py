from datetime import timezone


def iso(dt):
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


def ser_user(u):
    return {"id": u.id, "email": u.email, "name": u.name, "role": u.role, "is_active": u.is_active,
            "last_login": iso(u.last_login)}


def ser_asset(a, risk=None, counts=None):
    return {"id": a.id, "project_id": a.project_id, "value": a.value, "type": a.asset_type,
            "hostname": a.hostname, "ip": a.ip, "criticality": a.criticality, "exposure": a.exposure,
            "status": a.status, "authorization_status": a.authorization_status,
            "authorization_note": a.authorization_note, "dns_info": a.dns_info or {},
            "last_seen": iso(a.last_seen), "created_at": iso(a.created_at),
            "services": [{"id": s.id, "port": s.port, "protocol": s.protocol, "service": s.service,
                          "product": s.product, "version": s.version, "http_url": s.http_url,
                          "http_status": s.http_status, "http_title": s.http_title,
                          "last_seen": iso(s.last_seen)} for s in sorted(a.services, key=lambda s: s.port)],
            "technologies": [{"name": t.name, "version": t.version} for t in a.technologies],
            "risk_score": risk, "finding_counts": counts or {}}


def ser_finding(f, detail=False):
    v = f.vulnerability
    d = {"id": f.id, "project_id": f.project_id, "title": f.title, "severity": f.severity,
         "status": f.status, "asset_id": f.asset_id, "asset": f.asset.value if f.asset else None,
         "port": f.service.port if f.service else None, "source_tool": f.source_tool,
         "assignee": ({"id": f.assignee.id, "name": f.assignee.name} if f.assignee else None),
         "risk_score": f.risk_score, "occurrences": f.occurrences, "cve": v.cve,
         "first_seen": iso(f.first_seen), "last_seen": iso(f.last_seen)}
    if detail:
        d.update({"description": v.description, "remediation": v.remediation, "cvss": v.cvss,
                  "references": v.references or [], "tags": v.tags or [],
                  "exploit_known": v.exploit_known, "risk_factors": f.risk_factors or []})
    return d


def ser_scan(s, assets=None):
    assets = assets or {}
    done = sum(1 for j in s.jobs if j.status in ("completed", "failed", "cancelled"))
    return {"id": s.id, "project_id": s.project_id, "kind": s.kind, "scanners": s.scanners,
            "status": s.status, "created_at": iso(s.created_at), "started_at": iso(s.started_at),
            "finished_at": iso(s.finished_at),
            "progress": round(100 * done / len(s.jobs)) if s.jobs else 0,
            "jobs": [{"id": j.id, "asset_id": j.asset_id, "asset": assets.get(j.asset_id), "tool": j.tool,
                      "status": j.status, "error": j.error, "findings_created": j.findings_created,
                      "findings_updated": j.findings_updated} for j in s.jobs]}
