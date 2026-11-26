"""Scanner adapters. These run ONLY inside the worker container (never in the API process).
Safety: argument lists (no shell), validated targets, safe nuclei tag exclusions, hard timeout, cancel support."""
import re
import shutil
import socket
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse
import httpx
from .config import settings
from .lab import LAB, is_lab

HOST_RE = re.compile(r"^[a-z0-9]([a-z0-9.\-]{0,250}[a-z0-9])?$")
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 1433, 3000, 3306, 3389, 5432, 5900, 6379,
                8000, 8008, 8080, 8443, 9200, 11211, 27017]
HTTP_PORTS = {80, 443, 3000, 8000, 8008, 8080, 8443, 9200}


class ToolAborted(Exception):
    pass


class ToolError(Exception):
    pass


def validate_host(h: str) -> str:
    h = (h or "").strip().lower()
    if not HOST_RE.match(h) or h.startswith("-"):  # also blocks option injection
        raise ToolError(f"Refusing unsafe target {h!r}")
    return h


def run_cmd(args: list[str], cancelled, timeout=None) -> str:
    if not shutil.which(args[0]):
        raise ToolError(f"{args[0]} is not installed in this worker")
    timeout = timeout or settings.scan_timeout
    p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, shell=False)
    t0 = time.time()
    while True:
        try:
            out, err = p.communicate(timeout=1)
            break
        except subprocess.TimeoutExpired:
            if cancelled():
                p.kill(); p.communicate()
                raise ToolAborted("cancelled")
            if time.time() - t0 > timeout:
                p.kill(); p.communicate()
                raise ToolError(f"{args[0]} timed out after {timeout}s")
    if p.returncode not in (0,):
        raise ToolError(f"{args[0]} exited {p.returncode}: {err[:300]}")
    return out


def _tcp_open(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=1.0):
            return True
    except OSError:
        return False


def _http_probe(host: str, port: int) -> dict | None:
    for scheme in (("https",) if port in (443, 8443) else ("http", "https")):
        url = f"{scheme}://{host}:{port}/"
        try:
            r = httpx.get(url, timeout=5, verify=False, follow_redirects=False,
                          headers={"User-Agent": "NexaviseSentinel/1.0 (authorised assessment)"})
            m = re.search(r"<title[^>]*>(.*?)</title>", r.text[:20000], re.I | re.S)
            return {"service": scheme, "url": url, "status": r.status_code, "server": r.headers.get("server"),
                    "powered": r.headers.get("x-powered-by"), "title": (m.group(1).strip() if m else "")[:200]}
        except httpx.HTTPError:
            continue
    return None


def discover(host: str, cancelled) -> dict:
    """DNS lookup + TCP connect check of common ports + HTTP(S) probing. Non-intrusive."""
    host = validate_host(host)
    if is_lab(host):
        f = LAB.get(host)
        if not f:
            return {"ip": None, "dns": {}, "services": []}
        return {"ip": f["ip"], "dns": f["dns"], "services": [
            {k: s[k] for k in ("port", "protocol", "service", "http")} | {"product": s["product"], "version": s["version"]}
            for s in f["services"]]}
    dns, ip = {}, None
    try:
        infos = socket.getaddrinfo(host, None)
        dns["A"] = sorted({i[4][0] for i in infos if i[0] == socket.AF_INET})
        dns["AAAA"] = sorted({i[4][0] for i in infos if i[0] == socket.AF_INET6})
        ip = (dns["A"] or dns["AAAA"] or [None])[0]
        try:
            dns["PTR"] = [socket.gethostbyaddr(ip)[0]]
        except OSError:
            pass
    except socket.gaierror:
        return {"ip": None, "dns": {}, "services": []}
    with ThreadPoolExecutor(16) as ex:
        opened = [p for p, ok in zip(COMMON_PORTS, ex.map(lambda p: _tcp_open(ip, p), COMMON_PORTS)) if ok]
    services = []
    for p in opened:
        if cancelled():
            raise ToolAborted("cancelled")
        d = {"port": p, "protocol": "tcp", "service": None, "product": None, "version": None, "http": None}
        if p in HTTP_PORTS:
            h = _http_probe(host, p)
            if h:
                d["service"], d["http"] = h["service"], h
        services.append(d)
    return {"ip": ip, "dns": dns, "services": services}


def run_nmap(host: str, cancelled) -> tuple[str, list[dict]]:
    from .normalize import parse_nmap_xml
    host = validate_host(host)
    if is_lab(host):
        f = LAB.get(host, {"services": []})
        return "[simulated lab target - nmap output not generated]", [dict(s) for s in f["services"]]
    xml = run_cmd(["nmap", "-Pn", "-sT", "-sV", "--version-light", "-T3", "--top-ports", "200", "--open",
                   "-oX", "-", host], cancelled)
    return xml, parse_nmap_xml(xml)


def run_nuclei(host: str, urls: list[str], cancelled) -> tuple[str, list[dict]]:
    from .normalize import parse_jsonl
    host = validate_host(host)
    if is_lab(host):
        return "[simulated lab target - nuclei output not generated]", list(LAB.get(host, {}).get("nuclei", []))
    targets = []
    for u in urls or [f"https://{host}"]:
        pu = urlparse(u)
        if pu.scheme in ("http", "https") and validate_host(pu.hostname or "") == host:  # stay on this asset
            targets.append(u)
    args = ["nuclei", "-jsonl", "-silent", "-nc", "-disable-update-check", "-timeout", "5", "-rl", "50",
            "-etags", "dos,fuzz,intrusive,bruteforce"]  # non-destructive templates only
    for t in targets:
        args += ["-u", t]
    out = run_cmd(args, cancelled)
    return out, parse_jsonl(out)


def tool_status() -> dict:
    return {t: bool(shutil.which(t)) for t in ("nmap", "nuclei")}
