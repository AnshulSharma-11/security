"""End-to-end test of the complete workflow plus the security properties the assignment asks for."""
import pytest
from fastapi.testclient import TestClient
from app.db import SessionLocal
from app.main import app
from app.models import Organization, User
from app.normalize import clean, nuclei_finding, parse_nmap_xml
from app.security import hash_pw
from app.seed import seed

PW = "correct-horse-battery"


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        with SessionLocal() as db:
            assert seed(db, PW)
            other = Organization(name="Other Org"); db.add(other); db.flush()
            db.add(User(org_id=other.id, email="eve@other.example", name="Eve", role="admin", password_hash=hash_pw(PW)))
            db.add(User(org_id=other.id, email="mallory@other.example", name="Mallory", role="analyst", password_hash=hash_pw(PW)))
            db.commit()
        yield c


def login(c, email):
    r = c.post("/auth/login", json={"email": email, "password": PW})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}, r.json()


def test_login_and_refresh(client):
    assert client.post("/auth/login", json={"email": "admin@sentinel.example", "password": "nope-nope-nope"}).status_code == 401
    h, data = login(client, "admin@sentinel.example")
    assert data["projects"][0]["name"] == "Acme External Perimeter"
    r = client.post("/auth/refresh", json={"refresh_token": data["refresh_token"]})
    assert r.status_code == 200
    assert client.post("/auth/refresh", json={"refresh_token": data["access_token"]}).status_code == 401  # wrong token type
    assert client.get("/assets?project_id=1").status_code == 401


def test_login_throttle(client):
    for _ in range(5):
        assert client.post("/auth/login", json={"email": "mallory@other.example", "password": "wrong-wrong-1"}).status_code == 401
    assert client.post("/auth/login", json={"email": "mallory@other.example", "password": PW}).status_code == 429  # even the right password


def test_pipeline_outputs(client):
    h, data = login(client, "admin@sentinel.example")
    pid = data["projects"][0]["id"]
    assets = client.get(f"/assets?project_id={pid}", headers=h).json()
    assert len(assets) == 6 and all(a["status"] == "active" for a in assets)
    www = next(a for a in assets if a["value"].startswith("www"))
    assert www["ip"] == "203.0.113.10" and any(s["port"] == 443 for s in www["services"])
    fs = client.get(f"/findings?project_id={pid}", headers=h).json()
    titles = {f["title"] for f in fs["items"]}
    assert any("Path Traversal" in t for t in titles) and "Redis exposed" in titles
    top = fs["items"][0]
    detail = client.get(f"/findings/{top['id']}", headers=h).json()
    assert detail["risk_score"] > 70 and {f["name"] for f in detail["risk_factors"]} >= {"Severity", "Internet exposure", "Asset criticality"}
    assert detail["evidence"] and detail["remediation"] and detail["history"]
    paths = client.get(f"/attack-paths?project_id={pid}", headers=h).json()
    assert paths and paths[0]["target"].startswith(("db01", "files01"))
    pd = client.get(f"/attack-paths/{paths[0]['id']}", headers=h).json()
    assert pd["nodes"][0]["role"] == "entry" and pd["nodes"][-1]["role"] == "target" and len(pd["edges"]) == pd["hops"]
    ov = client.get(f"/risk/overview?project_id={pid}", headers=h).json()
    assert ov["risk_score"] > 0 and ov["trend"] and ov["top_paths"]
    assert client.get(f"/risk/top?project_id={pid}", headers=h).json()["assets"]


def test_dedup_on_rescan(client):
    h, data = login(client, "admin@sentinel.example")
    pid = data["projects"][0]["id"]
    before = client.get(f"/findings?project_id={pid}", headers=h).json()["total"]
    ids = [a["id"] for a in client.get(f"/assets?project_id={pid}", headers=h).json()]
    r = client.post("/scans", headers=h, json={"project_id": pid, "asset_ids": ids, "scanners": ["nmap", "nuclei"]})
    assert r.status_code == 202 and r.json()["status"] == "completed" and r.json()["progress"] == 100
    after = client.get(f"/findings?project_id={pid}", headers=h).json()
    assert after["total"] == before and max(f["occurrences"] for f in after["items"]) >= 2


def test_authorization_gate_and_rbac(client):
    ha, data = login(client, "analyst@sentinel.example")
    pid = data["projects"][0]["id"]
    r = client.post("/assets", headers=ha, json={"project_id": pid, "value": "new.acme.lab.sentinel.local", "confirm_authorized": True})
    assert r.status_code == 201 and r.json()["authorization_status"] == "pending"
    aid = r.json()["id"]
    assert client.post("/scans", headers=ha, json={"project_id": pid, "asset_ids": [aid]}).status_code == 403  # unapproved
    assert client.patch(f"/assets/{aid}", headers=ha, json={"authorization_status": "approved"}).status_code == 403
    assert client.post("/assets", headers=ha, json={"project_id": pid, "value": "x.example.com"}).status_code == 422  # must attest
    assert client.get("/admin/users", headers=ha).status_code == 403
    assert client.get("/admin/audit-logs", headers=ha).status_code == 403
    for bad in ("-oN /tmp/x", "a b", "ftp://x.com", "host/../etc"):
        assert client.post("/assets", headers=ha, json={"project_id": pid, "value": bad, "confirm_authorized": True}).status_code == 422
    hadm, _ = login(client, "admin@sentinel.example")
    assert client.patch(f"/assets/{aid}", headers=hadm, json={"authorization_status": "approved"}).status_code == 200
    s = client.post("/scans", headers=ha, json={"project_id": pid, "asset_ids": [aid], "scanners": ["nmap"]})
    assert s.status_code == 202
    f = client.get(f"/findings?project_id={pid}", headers=ha).json()["items"][0]
    assert client.patch(f"/findings/{f['id']}", headers=ha, json={"status": "accepted_risk"}).status_code == 403
    r = client.patch(f"/findings/{f['id']}", headers=ha, json={"status": "confirmed", "note": "verified"})
    assert r.status_code == 200 and r.json()["status"] == "confirmed"
    me = next(u for u in client.get("/users", headers=ha).json() if u["email"].startswith("analyst"))
    assert client.post(f"/findings/{f['id']}/assign", headers=ha, json={"user_id": me["id"]}).json()["assignee"]["id"] == me["id"]


def test_false_positive_drops_score(client):
    h, data = login(client, "admin@sentinel.example")
    pid = data["projects"][0]["id"]
    f = client.get(f"/findings?project_id={pid}&severity=critical", headers=h).json()["items"][0]
    assert client.patch(f"/findings/{f['id']}", headers=h, json={"status": "false_positive"}).json()["risk_score"] == 0
    assert client.patch(f"/findings/{f['id']}", headers=h, json={"status": "open"}).json()["risk_score"] > 50


def test_tenant_isolation(client):
    h, data = login(client, "admin@sentinel.example")
    pid = data["projects"][0]["id"]
    he, _ = login(client, "eve@other.example")
    fid = client.get(f"/findings?project_id={pid}", headers=h).json()["items"][0]["id"]
    aid = client.get(f"/assets?project_id={pid}", headers=h).json()[0]["id"]
    for url in (f"/projects/{pid}", f"/assets?project_id={pid}", f"/findings?project_id={pid}", f"/findings/{fid}",
                f"/assets/{aid}", f"/risk/overview?project_id={pid}", f"/attack-paths?project_id={pid}", f"/scans?project_id={pid}"):
        assert client.get(url, headers=he).status_code == 404, url
    assert client.post("/scans", headers=he, json={"project_id": pid, "asset_ids": [aid]}).status_code == 404
    assert client.patch(f"/findings/{fid}", headers=he, json={"status": "resolved"}).status_code == 404
    assert client.post("/reports", headers=he, json={"project_id": pid, "kind": "technical"}).status_code == 404


def test_reports_escape_and_audit(client):
    h, data = login(client, "admin@sentinel.example")
    pid = data["projects"][0]["id"]
    for kind in ("executive", "technical"):
        r = client.post("/reports", headers=h, json={"project_id": pid, "kind": kind})
        assert r.status_code == 201
        body = client.get(f"/reports/{r.json()['id']}", headers=h).json()["content"]
        assert "Overall risk" in body and "<script" not in body
    assert "attachment" in client.get(f"/reports/{r.json()['id']}/download", headers=h).headers["content-disposition"]
    actions = {a["action"] for a in client.get("/admin/audit-logs", headers=h).json()}
    assert {"auth.login", "auth.login_failed", "asset.create", "finding.status", "report.create", "assessment.start"} <= actions


def test_parsers_sanitise():
    xml = """<nmaprun><host><ports><port protocol="tcp" portid="6379"><state state="open"/>
             <service name="redis" product="Redis" version="5.0"/></port></ports></host></nmaprun>"""
    assert parse_nmap_xml(xml)[0]["port"] == 6379 and clean("a\x01b\x00") == "ab"
    with pytest.raises(Exception):  # XXE / entity expansion is rejected by defusedxml
        parse_nmap_xml('<!DOCTYPE x [<!ENTITY a "b">]><nmaprun>&a;</nmaprun>')
    f = nuclei_finding({"template-id": "t1", "matched-at": "https://h:8443/x", "info": {"name": "<img src=x onerror=1>", "severity": "bogus", "tags": "a,b"}})
    assert f["severity"] == "info" and f["port"] == 8443  # unknown severity is clamped, name stays plain text
    assert nuclei_finding({"info": {}}) is None
