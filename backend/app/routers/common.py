import ipaddress
import re
from urllib.parse import urlparse
from fastapi import HTTPException

HOST_RE = re.compile(r"^[a-z0-9]([a-z0-9.\-]{0,250}[a-z0-9])?$")
EMAIL_RE = r"^[^@\s]{1,64}@[^@\s]+\.[^@\s]+$"


def parse_target(raw: str) -> dict:
    v = (raw or "").strip().lower()
    if not v or len(v) > 300 or any(c.isspace() for c in v) or v.startswith("-"):
        raise HTTPException(422, "Enter a domain, hostname, IP address or http(s) URL")
    atype, host = None, v
    if "://" in v:
        u = urlparse(v)
        if u.scheme not in ("http", "https") or not u.hostname:
            raise HTTPException(422, "Only http:// and https:// URLs are supported")
        host, atype, v = u.hostname, "url", v.rstrip("/")
    elif "/" in v:
        raise HTTPException(422, "Paths are only allowed in full URLs (https://host/path)")
    try:
        ip = str(ipaddress.ip_address(host.strip("[]")))
        return {"value": v, "asset_type": atype or "ip", "hostname": None, "ip": ip}
    except ValueError:
        pass
    if not HOST_RE.match(host):
        raise HTTPException(422, "That does not look like a valid hostname")
    return {"value": v, "asset_type": atype or ("domain" if host.count(".") == 1 else "hostname"),
            "hostname": host, "ip": None}
