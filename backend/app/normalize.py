"""Parsing, sanitising, normalising and de-duplicating scanner output into a common finding format."""
import hashlib
import json
import re
from urllib.parse import urlparse
from defusedxml import ElementTree as ET
from sqlalchemy.orm import Session
from .models import (Asset, AssetService, Finding, FindingEvidence, FindingStatusHistory, SEVERITIES,
                     Technology, Vulnerability, now)

_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_SEV = {"informational": "info", "info": "info", "low": "low", "medium": "medium", "high": "high",
        "critical": "critical"}
EXPLOIT_TAGS = {"kev", "rce", "exploit", "unauth", "default-login"}


def clean(v, n=2000) -> str:
    """Strip control characters and cap length. Output is only ever rendered as text (React escapes it,
    reports html.escape it), this is defence in depth."""
    return _CTRL.sub("", str(v if v is not None else ""))[:n]


def sev(v) -> str:
    s = _SEV.get(str(v).lower(), "info")
    return s if s in SEVERITIES else "info"


# ---------------------------------------------------------------- parsers
def parse_nmap_xml(xml: str) -> list[dict]:
    root = ET.fromstring(xml)  # defusedxml: no entity expansion / external entities
    out = []
    for p in root.findall("host/ports/port"):
        st = p.find("state")
        if st is None or st.get("state") != "open":
            continue
        sv = p.find("service")
        g = (lambda k: clean(sv.get(k), 120) or None) if sv is not None else (lambda k: None)
        out.append({"port": int(p.get("portid")), "protocol": clean(p.get("protocol", "tcp"), 8),
                    "service": g("name"), "product": g("product"), "version": g("version"), "http": None})
    return out


def parse_jsonl(text: str) -> list[dict]:
    out = []
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("{"):
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return out


# ---------------------------------------------------------------- nmap rules -> findings
_FIX_NET = "Restrict the port with a firewall allow-list, bind the service to a private interface and require authentication and TLS."
EXPOSED = {  # port: (key, title, severity, cvss, why)
    21: ("exposed-ftp", "FTP service exposed", "medium", 5.3, "FTP sends credentials and data in cleartext."),
    23: ("exposed-telnet", "Telnet service exposed", "high", 7.5, "Telnet sends credentials and commands in cleartext and is trivially brute-forced."),
    445: ("exposed-smb", "SMB file sharing exposed", "high", 8.1, "SMB is a frequent target for credential relay, brute force and wormable exploits."),
    1433: ("exposed-mssql", "Microsoft SQL Server port exposed", "high", 7.5, "Database listeners should never be reachable from untrusted networks."),
    3306: ("exposed-mysql", "MySQL port exposed", "high", 7.5, "Database listeners should never be reachable from untrusted networks."),
    3389: ("exposed-rdp", "Remote Desktop (RDP) exposed", "high", 8.1, "RDP is a top ransomware entry point (brute force, BlueKeep-class bugs)."),
    5432: ("exposed-postgres", "PostgreSQL port exposed", "high", 7.5, "Database listeners should never be reachable from untrusted networks."),
    5900: ("exposed-vnc", "VNC remote desktop exposed", "high", 8.0, "VNC often uses weak or no authentication and no encryption."),
    6379: ("exposed-redis", "Redis exposed", "critical", 9.1, "Redis commonly runs without authentication and can be abused to write files or execute commands."),
    9200: ("exposed-elasticsearch", "Elasticsearch HTTP API exposed", "high", 7.5, "Open Elasticsearch nodes frequently leak or allow deletion of data."),
    11211: ("exposed-memcached", "Memcached exposed", "medium", 5.3, "Memcached has no authentication and is abused for data theft and amplification."),
    27017: ("exposed-mongodb", "MongoDB port exposed", "high", 7.5, "Database listeners should never be reachable from untrusted networks."),
}


def nmap_findings(services: list[dict]) -> list[dict]:
    out = []
    for s in services:
        r = EXPOSED.get(s["port"])
        if r:
            key, title, sv, cvss, why = r
            ver = " ".join(x for x in (s.get("product"), s.get("version")) if x)
            out.append({"key": f"nmap:{key}", "title": title, "severity": sv, "cvss": cvss, "cve": None,
                        "description": why, "remediation": _FIX_NET, "tags": ["exposure", "nmap"],
                        "references": [], "exploit_known": False, "port": s["port"], "tool": "nmap",
                        "evidence": f"{s['port']}/{s['protocol']} open {s.get('service') or '?'} {ver}".strip()})
    web = [s for s in services if (s.get("service") or "") in ("http", "https")]
    if any(s["service"] == "http" for s in web) and not any(s["service"] == "https" for s in web):
        s = next(s for s in web if s["service"] == "http")
        out.append({"key": "nmap:cleartext-http", "title": "Web service available without HTTPS", "severity": "low",
                    "cvss": 3.7, "cve": None, "description": "HTTP is served without a TLS-protected alternative.",
                    "remediation": "Serve the site over HTTPS and redirect HTTP to HTTPS (HSTS).", "tags": ["tls", "nmap"],
                    "references": [], "exploit_known": False, "port": s["port"], "tool": "nmap",
                    "evidence": f"{s['port']}/tcp open http, no https listener found"})
    return out


def nuclei_finding(item: dict) -> dict | None:
    info = item.get("info") or {}
    tid = clean(item.get("template-id") or item.get("templateID"), 120)
    if not tid:
        return None
    cls = info.get("classification") or {}
    cve = cls.get("cve-id")
    cve = clean(cve[0] if isinstance(cve, list) and cve else (cve or ""), 40) or None
    tags = info.get("tags") or []
    tags = [clean(t, 30) for t in (tags.split(",") if isinstance(tags, str) else tags)][:15]
    matched = clean(item.get("matched-at") or item.get("host"), 300)
    u = urlparse(matched if "://" in matched else f"//{matched}")
    try:
        port = u.port or (443 if u.scheme == "https" else 80 if u.scheme == "http" else None)
    except ValueError:
        port = None
    matcher = clean(item.get("matcher-name"), 60)
    ev = [f"Template: {tid}", f"Matched at: {matched}"]
    if matcher:
        ev.append(f"Matcher: {matcher}")
    for x in (item.get("extracted-results") or [])[:10]:
        ev.append(f"Extracted: {clean(x, 300)}")
    if item.get("curl-command"):
        ev.append(f"Reproduce: {clean(item['curl-command'], 500)}")
    try:
        cvss = float(cls.get("cvss-score")) if cls.get("cvss-score") is not None else None
    except (TypeError, ValueError):
        cvss = None
    refs = info.get("reference") or []
    refs = [clean(r, 300) for r in ([refs] if isinstance(refs, str) else refs)][:8]
    return {"key": f"nuclei:{tid}" + (f":{matcher}" if matcher else ""), "title": clean(info.get("name") or tid, 300),
            "severity": sev(info.get("severity")), "cvss": cvss, "cve": cve,
            "description": clean(info.get("description"), 3000),
            "remediation": clean(info.get("remediation") or "Apply the vendor fix or mitigation for this issue and re-scan.", 3000),
            "tags": tags, "references": refs, "exploit_known": bool(cve) or bool(EXPLOIT_TAGS & set(tags)),
            "port": port, "tool": "nuclei", "evidence": clean("\n".join(ev), 4000)}


# ---------------------------------------------------------------- persistence
def upsert_service(db: Session, asset: Asset, d: dict) -> tuple[AssetService, bool]:
    s = next((x for x in asset.services if x.port == d["port"] and x.protocol == d.get("protocol", "tcp")), None)
    new = s is None
    if new:
        s = AssetService(asset_id=asset.id, port=d["port"], protocol=d.get("protocol", "tcp"))
        db.add(s)
        asset.services.append(s)
    for k in ("service", "product", "version"):
        if d.get(k):
            setattr(s, k, clean(d[k], 120))
    h = d.get("http")
    if h:
        s.http_status, s.http_title = h.get("status"), clean(h.get("title"), 200)
        s.http_url = clean(h.get("url") or f"{'https' if d.get('service') == 'https' else 'http'}://{asset.hostname or asset.ip}:{d['port']}/", 300)
    s.state, s.last_seen = "open", now()
    return s, new


def upsert_tech(db: Session, asset: Asset, name: str, version: str | None, source: str):
    name = clean(name, 80)
    if name and not any(t.name.lower() == name.lower() for t in asset.technologies):
        t = Technology(asset_id=asset.id, name=name, version=clean(version, 60) or None, source=source)
        db.add(t)
        asset.technologies.append(t)


def tech_from_server(h: str | None):
    m = re.match(r"([A-Za-z\-]+)[/ ]?([\d][\w.\-]*)?", h or "")
    return (m.group(1), m.group(2)) if m else (None, None)


def apply_discovery(db: Session, asset: Asset, res: dict):
    """Persist DNS, services, technologies and derive status/exposure."""
    import ipaddress
    had_services = bool(asset.services)
    known = {(s.port, s.protocol) for s in asset.services}
    asset.dns_info = res.get("dns") or {}
    if res.get("ip"):
        asset.ip = res["ip"]
    added = False
    for d in res.get("services", []):
        _, new = upsert_service(db, asset, d)
        added |= new
        h = d.get("http") or {}
        n, v = tech_from_server(h.get("server"))
        if n:
            upsert_tech(db, asset, n, v, "http-headers")
        if d.get("product") and d.get("service") in ("http", "https"):
            upsert_tech(db, asset, d["product"], d.get("version"), "service-banner")
    if res.get("services") or res.get("dns", {}).get("A"):
        asset.last_seen = now()
        # active unless this is a previously-known asset that grew new services (analyst should look)
        asset.status = "needs_review" if (had_services and added and known) else "active"
    else:
        asset.status = "inactive"
    if asset.exposure == "unknown" and asset.ip:
        try:
            asset.exposure = "internet" if ipaddress.ip_address(asset.ip).is_global else "internal"
        except ValueError:
            pass


def upsert_finding(db: Session, asset: Asset, nf: dict, user_id=None) -> tuple[Finding, bool]:
    v = db.query(Vulnerability).filter_by(key=nf["key"]).first()
    if not v:
        v = Vulnerability(key=nf["key"], title=nf["title"], severity=nf["severity"], cvss=nf.get("cvss"),
                          cve=nf.get("cve"), description=nf["description"], remediation=nf["remediation"],
                          references=nf.get("references", []), tags=nf.get("tags", []),
                          exploit_known=nf.get("exploit_known", False))
        db.add(v)
        db.flush()
    svc = next((s for s in asset.services if nf.get("port") and s.port == nf["port"]), None)
    dedup = hashlib.sha256(f"{asset.id}|{nf['key']}|{nf.get('port') or ''}".encode()).hexdigest()[:40]
    f = db.query(Finding).filter_by(project_id=asset.project_id, dedup_key=dedup).first()
    created = f is None
    if created:
        f = Finding(project_id=asset.project_id, asset_id=asset.id, vulnerability_id=v.id, dedup_key=dedup,
                    service_id=svc.id if svc else None, title=nf["title"], severity=nf["severity"],
                    source_tool=nf["tool"], status="open")
        db.add(f)
        db.flush()
        db.add(FindingStatusHistory(finding_id=f.id, new_status="open", note=f"Detected by {nf['tool']}"))
    else:
        f.occurrences += 1
        f.last_seen = now()
        if f.status == "resolved":  # it came back
            db.add(FindingStatusHistory(finding_id=f.id, old_status="resolved", new_status="open",
                                        note=f"Re-detected by {nf['tool']}"))
            f.status = "open"
    last = db.query(FindingEvidence).filter_by(finding_id=f.id).order_by(FindingEvidence.id.desc()).first()
    if not last or last.content != nf["evidence"]:  # identical evidence is not stored twice
        db.add(FindingEvidence(finding_id=f.id, tool=nf["tool"], content=nf["evidence"]))
    return f, created
