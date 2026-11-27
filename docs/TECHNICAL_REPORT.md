# Nexavise Sentinel: Technical Report

## 1. Scope delivered
Every required capability in the brief is implemented end to end: authentication with Admin/Analyst roles, projects
with isolated data, audit log; asset inventory and discovery; two isolated scanner jobs (Nmap, Nuclei) with normalised and
de-duplicated findings; full finding workflow (six statuses, evidence, remediation, assignment, history); a transparent
risk engine; attack-path analysis with an interactive visual; HTML executive and technical reports; all nine UI screens;
all listed API endpoints; Docker Compose deployment; demo data and a safe lab target.

I chose depth on the core workflow over breadth: a partial feature set that works from asset to report, with the security
controls actually enforced and tested.

## 2. Key design decisions
**Pipeline separation.** The API only validates, authorises and *enqueues*. Execution happens in `worker_core.process_job`
inside a separate image that is the only place nmap and nuclei exist. The same code path runs in tests and seeding, so
the demo exercises the real parsers, de-duplication, risk and graph code.

**Normalisation and de-duplication.** Each tool result becomes one dict (`key`, `title`, `severity`, `cvss`, `cve`, `tags`,
`port`, `evidence`, ...). `Vulnerability` is the issue catalogue; `Finding` is an occurrence on an asset.
`dedup_key = sha256(asset | issue key | port)`, unique per project. A repeat updates `last_seen` and `occurrences`, stores new
evidence only if it differs, and re-opens a finding that had been resolved.

**Transparent risk.** A sum of six named, capped factors rather than a black-box number. Each finding stores its factor list
(points, maximum, reason). Triage changes feed back immediately. See README for the formula and rationale: severity and CVSS
describe the weakness; exposure and criticality describe context; exploitability describes likelihood; path involvement rewards
fixing weaknesses that chain.

**Attack paths.** Modelled as a directed graph: nodes are assets; edges are analyst-entered relationships plus inferred same-/24
adjacency. A node is a foothold if it has an active medium-or-higher finding. Depth-limited DFS from internet-exposed footholds
finds routes to criticality 4 to 5 assets; the best route per (entry, target) is kept and persisted into
`attack_paths / _nodes / _edges` with a natural-language explanation and a factor breakdown. Path involvement feeds back into
finding scores (+5), and the best path contributes 30% of the project score.

**Why not Neo4j.** The brief allows an equivalent. At MVP scale a relational graph avoids a fourth service, keeps tenant
isolation in one place, and is easier to test. The path module is isolated behind `analyze_paths`/`path_dict` so it can be swapped.

## 3. Security controls and how they map to the brief
| Requirement | Control | Evidence |
|---|---|---|
| Only scan authorised assets | Attestation on creation; analysts' assets are `pending`; admin approval; 403 at `/scans`; **re-checked in the worker** | `test_authorization_gate_and_rbac` |
| Isolated workers | Separate worker image, non-root, `cap_drop: ALL`, read-only FS, mem/pid limits, dedicated `scan` network, DB/Redis on internal network | `docker-compose.yml`, `Dockerfile.worker` |
| No destructive behaviour | Nmap connect scan with light version detection; nuclei `-etags dos,fuzz,intrusive,bruteforce`; no exploitation, persistence or credential harvesting code exists | `scanners.py` |
| Validate/sanitise scanner output | defusedxml (no XXE/entity expansion), JSON parsed defensively, control characters stripped, lengths capped, severity clamped to a whitelist; output only rendered as text or `html.escape`d in a sandboxed iframe | `test_parsers_sanitise`, `test_reports_escape_and_audit` |
| Tenant/project authorisation on every operation | `project_for()` resolves every project through the caller's organisation; item routes load the item then check its project; cross-tenant -> 404 | `test_tenant_isolation` (8 routes) |
| No hard-coded secrets | `pydantic-settings` from env; no default `SECRET_KEY`; compose uses `${VAR:?}`; demo password generated | `config.py`, `.env.example` |
| Audit log | Logins (including failures), project/asset/scan/finding/report/user/attack-path actions, worker scan outcomes | `test_reports_escape_and_audit` |
| Secure auth | bcrypt, short-lived access tokens + refresh tokens with type claim, login throttling, deactivated users rejected | `test_login_and_refresh` |
| Command injection | Targets validated by allow-list regex, must not start with `-`; subprocess argument lists with `shell=False`; nuclei URLs must stay on the asset's host | `parse_target`, `validate_host` |

Threats considered: SSRF/scope creep (host pinned to the asset, approval gate), option injection, XML bombs, stored XSS via
scanner output, IDOR across tenants, privilege escalation (analyst approving assets or accepting risk), worker resource
exhaustion (timeout, cancellation, limits), brute-force login.

## 4. Testing
`backend/tests/test_flow.py` (9 tests): login/refresh/token-type, login throttling, full pipeline outputs on lab targets (assets, services, findings,
evidence, score factors, attack paths, overview), de-duplication on re-scan, authorisation gate and RBAC, false-positive score
behaviour, tenant isolation, report escaping and audit coverage, parser hardening.

## 5. Known gaps and next steps
See "Assumptions and limitations" in the README. Highest priority: run the container build and a live Nuclei lab scan, add per-IP throttling, let the worker report results through a scoped API instead of direct DB access, and add
Neo4j-backed path queries and scheduled re-scans with change detection.
