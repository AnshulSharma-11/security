# Nexavise Sentinel (MVP)

Authorised attack-surface discovery, vulnerability assessment, transparent risk scoring and attack-path
intelligence. Built for the 7-day Nexavise Consulting assignment. It answers one question:
**what do we have, what is vulnerable, what matters most, and how could weaknesses connect?**

```
Authorised asset -> Discovery -> Scan job (Redis queue) -> Scanner worker (nmap / nuclei)
   -> Parser + sanitiser -> Normalised, de-duplicated finding -> Risk engine -> Attack graph -> Dashboard / Report
```

## Quick start (Docker Compose)

```bash
cp .env.example .env
python3 -c "import secrets; print(secrets.token_urlsafe(48))"   # paste into SENTINEL_SECRET_KEY and POSTGRES_PASSWORD
docker compose up --build -d
docker compose exec api python -m app.seed       # demo data + login credentials (printed once)
```

Open **http://localhost:8080** (UI) or **http://localhost:8000/docs** (OpenAPI / Swagger).
The seed uses simulated lab targets (`*.lab.sentinel.local`), so the whole demo runs without scanning anything.

To also try the real nmap + nuclei adapters against a deliberately vulnerable local app:

```bash
docker compose --profile lab up -d lab-target
```
Add `lab-target` as an asset (tick the authorisation box, then approve it as admin) and scan it.
It is only reachable from the isolated `scan` network.

## Local development without Docker

```bash
cd backend && python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt
export SENTINEL_SECRET_KEY=$(python -c "import secrets;print(secrets.token_urlsafe(48))")
export SENTINEL_EAGER=true            # runs jobs inline: dev/tests only, bypasses worker isolation
python -m app.seed && uvicorn app.main:app --reload
# second terminal
cd frontend && npm install && npm run dev   # http://localhost:5173 (proxies /api -> :8000)
cd backend && python -m pytest -q           # 9 end-to-end tests
```

## Demo walkthrough (5 to 10 minutes)

1. **Sign in** as the admin and choose the project. Sign in as the analyst in a private window to show role differences.
2. **Attack surface**: add `new.acme.lab.sentinel.local` as the analyst. It stays *waiting for an administrator*. Try to scan it: the API refuses (403). Approve it as admin.
3. **Scan center**: run *Discovery* (DNS, ports, HTTP, technologies fill in), then *Start scan* with nmap + nuclei. Watch jobs progress; cancel works too.
4. **Vulnerabilities**: filter by severity/status, open a finding. See evidence, remediation, status history and **"Why this score"**. Mark a finding false positive and watch the score and attack paths change. Assign it to a colleague.
5. **Dashboard**: project risk, trend, most dangerous path, top assets and findings.
6. **Attack paths**: `portal` (Tomcat default login) -> `app01` (Jenkins default login) -> `db01` (exposed Redis). Hover edges for the reason; read "Why this is risky" and the path score breakdown.
7. **Reports**: generate the executive summary and the technical report; preview and download.
8. **Administration**: users and roles, audit log (every step above is recorded), integrations status.

## Architecture

| Layer | Choice |
|---|---|
| Frontend | React 18 + TypeScript + Tailwind (Vite), served by nginx |
| API | Python FastAPI, JWT access + refresh tokens, OpenAPI at `/docs` |
| Database | PostgreSQL (SQLite for tests); 20 tables, see `docs/schema.sql` |
| Queue / worker | Redis + Celery. **Separate worker image** is the only one containing nmap and nuclei |
| Graph | Relational graph (assets = nodes, links + inferred /24 adjacency = edges) searched in Python |
| Scanners | Nmap (services/versions + risky exposed-service rules), Nuclei (JSONL, non-destructive tags only), built-in discovery (DNS, TCP connect, HTTP probe) |

Code map: `backend/app/routers/*` (API), `normalize.py` (parse, sanitise, dedupe), `scanners.py` (adapters),
`worker_core.py` (job execution), `risk.py` (scoring), `attackpath.py` (graph + path search), `reportgen.py`.

## Risk score (0 to 100, always explained)

Severity (max 35) + CVSS (10) + internet exposure (20) + asset criticality x4 (20) + known exploitability (10) +
attack-path involvement (5). False positive / resolved = 0; accepted risk = -60%.
Each factor and its reason is stored with the finding and shown in the UI and reports. Project risk =
0.7 x mean of the top 5 finding scores + 0.3 x the best attack-path score.

## Attack paths

A *foothold* is an active finding of severity medium or higher. An attacker with a foothold on asset A can reach
assets adjacent to A (explicit relationship, or same /24). Paths start at an internet-exposed foothold and end at a
criticality 4 or 5 asset that has a weakness (max 4 hops, best path per entry/target pair). Path score =
0.6 x mean weakness risk + 6 x target criticality + 10 (internet entry) - 3 per extra hop.
Scoring and paths are recomputed after every scan, status change, criticality/exposure change and relationship edit.

## Security controls (summary; details in `docs/TECHNICAL_REPORT.md`)

* **Authorisation gate**: assets need an attestation; analysts' assets are *pending* until an admin approves. Enforced at request time (403) and **again in the worker** at execution time.
* **Isolation**: API image has no scanners; worker is a separate non-root container with `cap_drop: ALL`, read-only filesystem, memory/pid limits and its own network; DB/Redis are on an internal network.
* **Tenant isolation**: every route resolves the project through the caller's organisation; cross-tenant access returns 404 (tested).
* **RBAC**: Admin (users, approvals, accepted risk, audit log) vs Analyst (assets, scans of approved assets, triage).
* **Input/output safety**: target validation blocks option injection (`-oN`), no shell, argument lists only; nuclei excludes `dos,fuzz,intrusive,bruteforce`; XML via defusedxml; control characters stripped and lengths capped; React escapes output; reports `html.escape` everything and render in a sandboxed iframe.
* **Secrets**: all from environment (`.env`, git-ignored); the API refuses to start without `SENTINEL_SECRET_KEY`; demo password is generated at seed time.
* **Audit log** for logins (incl. failures), asset/scan/finding/report/user actions and worker events.
* bcrypt password hashing, login throttling (5 failures / 15 min), JWT type separation (access vs refresh), security headers.

## API surface

All endpoints from the assignment exist (`/auth/login|refresh`, `/projects`, `/assets`, `/discovery`, `/scans` (+cancel),
`/findings` (+assign), `/risk/overview|top`, `/attack-paths` (+analyze), `/reports`), plus `/users`, `/admin/users`,
`/admin/audit-logs`, `/admin/integrations`, `/assets/{id}/links`. Browse them at `/docs`.

## Assumptions and limitations (honest list)

* **Verified here:** all API behaviour, the full pipeline on simulated targets, the parsers (including hostile input), and a production UI build. The real **discovery and Nmap adapters were also run** against live local services (HTTP banner, technology and an exposed Redis port were detected and scored; a job queued for an unapproved asset was rejected inside the worker).
* **Not verified here:** the Docker images/compose file (no Docker available) and the **Nuclei** adapter against the real binary (only its parser, using nuclei-format fixtures). Run `docker compose build` and one lab scan before the demo; fix the nuclei version/arch in `Dockerfile.worker` if the download URL has changed.
* Nmap scans an explicit port list (common web/admin ports plus every port the exposed-service rules cover) rather than nmap's default top-1000, which omits Redis. Ports outside the list are not scanned.
* Graph search runs in Python over relational tables rather than Neo4j. Fine for hundreds of assets; Neo4j would be the next step.
* Relationships between assets are explicit (user-entered) plus inferred same-/24; real traffic/topology ingestion is out of scope.
* Tables are created on API start; an Alembic baseline migration is included (`alembic upgrade head`) and `docs/schema.sql` is generated for review. Incremental migrations start from that baseline.
* Login throttling (5 failures per 15 minutes per account) is stored in the audit log, so it is shared across API processes; it does not yet throttle by IP. Tokens are held in `sessionStorage` (cleared on tab close; httpOnly cookies + CSRF would be stronger).
* The worker needs database access to persist results, so a compromised worker could read the DB. Next step: have the worker post results to the API with a scoped token.
* Roles are a column on `users` (admin | analyst) instead of a separate `roles` table.
* No scheduling/continuous monitoring, no PDF export (reports are self-contained HTML).
