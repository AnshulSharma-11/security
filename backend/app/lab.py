"""Safe demo targets. Hostnames under .lab.sentinel.local never resolve and are never scanned over the
network: the scanner adapters return these canned results (in the same formats real nmap/nuclei emit),
so the full pipeline can be demonstrated without touching any real system."""

LAB_SUFFIX = ".lab.sentinel.local"


def is_lab(host: str | None) -> bool:
    return bool(host) and host.lower().endswith(LAB_SUFFIX)


def _nj(tid, name, sev, matched, tags, cve=None, cvss=None, desc="", rem="", extracted=None, refs=None):
    cls = {"cve-id": [cve] if cve else None, "cvss-score": cvss}
    return {"template-id": tid, "matched-at": matched, "host": matched, "extracted-results": extracted or [],
            "info": {"name": name, "severity": sev, "tags": tags, "description": desc, "remediation": rem,
                     "reference": refs or [], "classification": cls}}


def _svc(port, service, product=None, version=None, http=None):
    return {"port": port, "protocol": "tcp", "service": service, "product": product, "version": version,
            "http": http}


LAB = {
    "www.acme.lab.sentinel.local": {
        "ip": "203.0.113.10", "dns": {"A": ["203.0.113.10"], "PTR": ["www.acme.example"]},
        "services": [
            _svc(80, "http", "Apache httpd", "2.4.49", {"status": 301, "title": "Moved", "server": "Apache/2.4.49 (Unix)"}),
            _svc(443, "https", "Apache httpd", "2.4.49", {"status": 200, "title": "Acme Corp", "server": "Apache/2.4.49 (Unix)"})],
        "nuclei": [
            _nj("CVE-2021-41773", "Apache HTTP Server 2.4.49 - Path Traversal and RCE", "critical",
                "https://www.acme.lab.sentinel.local/cgi-bin/.%2e/.%2e/etc/passwd", ["cve", "kev", "rce", "apache"],
                "CVE-2021-41773", 9.8,
                "A flaw in path normalisation in Apache 2.4.49 allows files outside the document root to be read and, with CGI enabled, remote code execution.",
                "Upgrade Apache HTTP Server to 2.4.51 or later and ensure 'Require all denied' is set on directories outside the document root.",
                ["root:x:0:0:root:/root:/bin/bash"], ["https://nvd.nist.gov/vuln/detail/CVE-2021-41773"]),
            _nj("git-config", "Git Config File Exposure", "medium", "https://www.acme.lab.sentinel.local/.git/config",
                ["exposure", "git"], desc="The /.git/config file is publicly readable and can leak repository URLs and credentials.",
                rem="Block access to dot-directories at the web server and remove .git from deployed artifacts."),
            _nj("http-missing-security-headers", "Missing Security Headers", "info", "https://www.acme.lab.sentinel.local/",
                ["misconfig", "headers"], desc="Content-Security-Policy and X-Frame-Options are not set.",
                rem="Add CSP, X-Frame-Options and X-Content-Type-Options response headers.")]},
    "portal.acme.lab.sentinel.local": {
        "ip": "203.0.113.25", "dns": {"A": ["203.0.113.25"]},
        "services": [
            _svc(443, "https", "nginx", "1.18.0", {"status": 200, "title": "Acme Customer Portal", "server": "nginx/1.18.0"}),
            _svc(8080, "http", "Apache Tomcat", "9.0.30", {"status": 200, "title": "Apache Tomcat/9.0.30", "server": "Apache-Coyote/1.1"})],
        "nuclei": [
            _nj("tomcat-default-login", "Apache Tomcat Manager Default Credentials", "high",
                "http://portal.acme.lab.sentinel.local:8080/manager/html", ["default-login", "tomcat"],
                desc="The Tomcat manager application accepts a vendor default credential pair, allowing deployment of arbitrary WAR files.",
                rem="Change all default credentials, restrict /manager to an admin network and remove it if unused.",
                extracted=["tomcat:***"]),
            _nj("CVE-2020-1938", "Apache Tomcat AJP File Read/Inclusion (Ghostcat)", "high",
                "portal.acme.lab.sentinel.local:8009", ["cve", "tomcat", "ajp"], "CVE-2020-1938", 8.1,
                "The AJP connector is exposed and allows reading web application files.",
                "Upgrade to Tomcat 9.0.31+, disable the AJP connector or require a secret.")]},
    "app01.corp.lab.sentinel.local": {
        "ip": "10.20.1.21", "dns": {"A": ["10.20.1.21"]},
        "services": [
            _svc(22, "ssh", "OpenSSH", "7.4"),
            _svc(8080, "http", "Jetty", "9.4.z", {"status": 403, "title": "Jenkins", "server": "Jetty(9.4.z-SNAPSHOT)"})],
        "nuclei": [
            _nj("jenkins-default-login", "Jenkins Default Login", "high", "http://app01.corp.lab.sentinel.local:8080/login",
                ["default-login", "jenkins"], desc="Jenkins accepts a default administrative credential; the script console allows arbitrary command execution on the build host.",
                rem="Set strong unique admin credentials, enable SSO and disable the script console for non-admins.")]},
    "db01.corp.lab.sentinel.local": {
        "ip": "10.20.1.30", "dns": {"A": ["10.20.1.30"]},
        "services": [_svc(22, "ssh", "OpenSSH", "8.9"), _svc(5432, "postgresql", "PostgreSQL DB", "13.4"),
                     _svc(6379, "redis", "Redis key-value store", "5.0.7")],
        "nuclei": []},
    "files01.corp.lab.sentinel.local": {
        "ip": "10.20.2.15", "dns": {"A": ["10.20.2.15"]},
        "services": [_svc(445, "microsoft-ds", "Samba smbd", "4.6.2")],
        "nuclei": []},
    "dev01.corp.lab.sentinel.local": {
        "ip": "10.20.1.45", "dns": {"A": ["10.20.1.45"]},
        "services": [_svc(23, "telnet", "Linux telnetd"), _svc(22, "ssh", "OpenSSH", "7.2")],
        "nuclei": []},
}
