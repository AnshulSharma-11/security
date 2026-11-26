-- Nexavise Sentinel schema (PostgreSQL). Generated from app/models.py; the API also runs create_all() on start.

CREATE TABLE audit_logs (
	id SERIAL NOT NULL, 
	org_id INTEGER, 
	project_id INTEGER, 
	user_id INTEGER, 
	user_email VARCHAR(254), 
	action VARCHAR(60) NOT NULL, 
	target_type VARCHAR(30), 
	target_id INTEGER, 
	detail TEXT, 
	ip_address VARCHAR(45), 
	created_at TIMESTAMP WITH TIME ZONE, 
	PRIMARY KEY (id)
);

CREATE INDEX ix_audit_logs_org_id ON audit_logs (org_id);
CREATE INDEX ix_audit_logs_project_id ON audit_logs (project_id);
CREATE INDEX ix_audit_logs_action ON audit_logs (action);

CREATE TABLE organizations (
	id SERIAL NOT NULL, 
	name VARCHAR(120) NOT NULL, 
	created_at TIMESTAMP WITH TIME ZONE, 
	PRIMARY KEY (id), 
	UNIQUE (name)
);


CREATE TABLE vulnerabilities (
	id SERIAL NOT NULL, 
	key VARCHAR(200) NOT NULL, 
	title VARCHAR(300) NOT NULL, 
	severity VARCHAR(12) NOT NULL, 
	cvss FLOAT, 
	cve VARCHAR(40), 
	description TEXT, 
	remediation TEXT, 
	"references" JSON, 
	tags JSON, 
	exploit_known BOOLEAN, 
	PRIMARY KEY (id), 
	UNIQUE (key)
);


CREATE TABLE projects (
	id SERIAL NOT NULL, 
	org_id INTEGER NOT NULL, 
	name VARCHAR(120) NOT NULL, 
	description TEXT, 
	created_at TIMESTAMP WITH TIME ZONE, 
	PRIMARY KEY (id), 
	UNIQUE (org_id, name), 
	FOREIGN KEY(org_id) REFERENCES organizations (id)
);

CREATE INDEX ix_projects_org_id ON projects (org_id);

CREATE TABLE users (
	id SERIAL NOT NULL, 
	org_id INTEGER NOT NULL, 
	email VARCHAR(254) NOT NULL, 
	name VARCHAR(120) NOT NULL, 
	password_hash VARCHAR(100) NOT NULL, 
	role VARCHAR(16) NOT NULL, 
	is_active BOOLEAN NOT NULL, 
	created_at TIMESTAMP WITH TIME ZONE, 
	last_login TIMESTAMP WITH TIME ZONE, 
	PRIMARY KEY (id), 
	FOREIGN KEY(org_id) REFERENCES organizations (id)
);

CREATE INDEX ix_users_org_id ON users (org_id);
CREATE UNIQUE INDEX ix_users_email ON users (email);

CREATE TABLE assets (
	id SERIAL NOT NULL, 
	project_id INTEGER NOT NULL, 
	value VARCHAR(300) NOT NULL, 
	asset_type VARCHAR(16) NOT NULL, 
	hostname VARCHAR(253), 
	ip VARCHAR(45), 
	criticality INTEGER NOT NULL, 
	exposure VARCHAR(16) NOT NULL, 
	status VARCHAR(16) NOT NULL, 
	authorization_status VARCHAR(16) NOT NULL, 
	authorization_note TEXT, 
	authorized_by INTEGER, 
	authorized_at TIMESTAMP WITH TIME ZONE, 
	dns_info JSON, 
	last_seen TIMESTAMP WITH TIME ZONE, 
	created_by INTEGER, 
	created_at TIMESTAMP WITH TIME ZONE, 
	PRIMARY KEY (id), 
	UNIQUE (project_id, value), 
	FOREIGN KEY(project_id) REFERENCES projects (id), 
	FOREIGN KEY(authorized_by) REFERENCES users (id), 
	FOREIGN KEY(created_by) REFERENCES users (id)
);

CREATE INDEX ix_assets_project_id ON assets (project_id);

CREATE TABLE reports (
	id SERIAL NOT NULL, 
	project_id INTEGER NOT NULL, 
	kind VARCHAR(16) NOT NULL, 
	title VARCHAR(200), 
	content TEXT, 
	created_by INTEGER, 
	created_at TIMESTAMP WITH TIME ZONE, 
	PRIMARY KEY (id), 
	FOREIGN KEY(project_id) REFERENCES projects (id), 
	FOREIGN KEY(created_by) REFERENCES users (id)
);

CREATE INDEX ix_reports_project_id ON reports (project_id);

CREATE TABLE risk_scores (
	id SERIAL NOT NULL, 
	project_id INTEGER NOT NULL, 
	score FLOAT NOT NULL, 
	detail JSON, 
	created_at TIMESTAMP WITH TIME ZONE, 
	PRIMARY KEY (id), 
	FOREIGN KEY(project_id) REFERENCES projects (id)
);

CREATE INDEX ix_risk_scores_project_id ON risk_scores (project_id);

CREATE TABLE scans (
	id SERIAL NOT NULL, 
	project_id INTEGER NOT NULL, 
	kind VARCHAR(16) NOT NULL, 
	scanners JSON, 
	status VARCHAR(16) NOT NULL, 
	cancel_requested BOOLEAN, 
	created_by INTEGER, 
	created_at TIMESTAMP WITH TIME ZONE, 
	started_at TIMESTAMP WITH TIME ZONE, 
	finished_at TIMESTAMP WITH TIME ZONE, 
	PRIMARY KEY (id), 
	FOREIGN KEY(project_id) REFERENCES projects (id), 
	FOREIGN KEY(created_by) REFERENCES users (id)
);

CREATE INDEX ix_scans_project_id ON scans (project_id);

CREATE TABLE asset_links (
	id SERIAL NOT NULL, 
	project_id INTEGER NOT NULL, 
	src_id INTEGER NOT NULL, 
	dst_id INTEGER NOT NULL, 
	relation VARCHAR(30) NOT NULL, 
	note VARCHAR(300), 
	created_by INTEGER, 
	PRIMARY KEY (id), 
	UNIQUE (src_id, dst_id, relation), 
	FOREIGN KEY(project_id) REFERENCES projects (id), 
	FOREIGN KEY(src_id) REFERENCES assets (id), 
	FOREIGN KEY(dst_id) REFERENCES assets (id), 
	FOREIGN KEY(created_by) REFERENCES users (id)
);

CREATE INDEX ix_asset_links_project_id ON asset_links (project_id);

CREATE TABLE asset_services (
	id SERIAL NOT NULL, 
	asset_id INTEGER NOT NULL, 
	port INTEGER NOT NULL, 
	protocol VARCHAR(8), 
	service VARCHAR(60), 
	product VARCHAR(120), 
	version VARCHAR(80), 
	state VARCHAR(12), 
	http_url VARCHAR(300), 
	http_status INTEGER, 
	http_title VARCHAR(200), 
	last_seen TIMESTAMP WITH TIME ZONE, 
	PRIMARY KEY (id), 
	UNIQUE (asset_id, port, protocol), 
	FOREIGN KEY(asset_id) REFERENCES assets (id)
);

CREATE INDEX ix_asset_services_asset_id ON asset_services (asset_id);

CREATE TABLE attack_paths (
	id SERIAL NOT NULL, 
	project_id INTEGER NOT NULL, 
	entry_asset_id INTEGER NOT NULL, 
	target_asset_id INTEGER NOT NULL, 
	hops INTEGER NOT NULL, 
	risk_score FLOAT NOT NULL, 
	score_factors JSON, 
	explanation TEXT, 
	created_at TIMESTAMP WITH TIME ZONE, 
	PRIMARY KEY (id), 
	FOREIGN KEY(project_id) REFERENCES projects (id), 
	FOREIGN KEY(entry_asset_id) REFERENCES assets (id), 
	FOREIGN KEY(target_asset_id) REFERENCES assets (id)
);

CREATE INDEX ix_attack_paths_project_id ON attack_paths (project_id);

CREATE TABLE scan_jobs (
	id SERIAL NOT NULL, 
	scan_id INTEGER NOT NULL, 
	asset_id INTEGER NOT NULL, 
	tool VARCHAR(16) NOT NULL, 
	status VARCHAR(16) NOT NULL, 
	error TEXT, 
	celery_id VARCHAR(60), 
	findings_created INTEGER, 
	findings_updated INTEGER, 
	started_at TIMESTAMP WITH TIME ZONE, 
	finished_at TIMESTAMP WITH TIME ZONE, 
	PRIMARY KEY (id), 
	FOREIGN KEY(scan_id) REFERENCES scans (id), 
	FOREIGN KEY(asset_id) REFERENCES assets (id)
);

CREATE INDEX ix_scan_jobs_scan_id ON scan_jobs (scan_id);

CREATE TABLE technologies (
	id SERIAL NOT NULL, 
	asset_id INTEGER NOT NULL, 
	name VARCHAR(80) NOT NULL, 
	version VARCHAR(60), 
	source VARCHAR(30), 
	PRIMARY KEY (id), 
	UNIQUE (asset_id, name), 
	FOREIGN KEY(asset_id) REFERENCES assets (id)
);

CREATE INDEX ix_technologies_asset_id ON technologies (asset_id);

CREATE TABLE attack_path_nodes (
	id SERIAL NOT NULL, 
	path_id INTEGER NOT NULL, 
	position INTEGER NOT NULL, 
	asset_id INTEGER NOT NULL, 
	role VARCHAR(10) NOT NULL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(path_id) REFERENCES attack_paths (id), 
	FOREIGN KEY(asset_id) REFERENCES assets (id)
);

CREATE INDEX ix_attack_path_nodes_path_id ON attack_path_nodes (path_id);

CREATE TABLE findings (
	id SERIAL NOT NULL, 
	project_id INTEGER NOT NULL, 
	asset_id INTEGER NOT NULL, 
	vulnerability_id INTEGER NOT NULL, 
	service_id INTEGER, 
	dedup_key VARCHAR(64) NOT NULL, 
	title VARCHAR(300) NOT NULL, 
	severity VARCHAR(12) NOT NULL, 
	status VARCHAR(16) NOT NULL, 
	assignee_id INTEGER, 
	source_tool VARCHAR(16), 
	occurrences INTEGER, 
	risk_score FLOAT, 
	risk_factors JSON, 
	first_seen TIMESTAMP WITH TIME ZONE, 
	last_seen TIMESTAMP WITH TIME ZONE, 
	PRIMARY KEY (id), 
	UNIQUE (project_id, dedup_key), 
	FOREIGN KEY(project_id) REFERENCES projects (id), 
	FOREIGN KEY(asset_id) REFERENCES assets (id), 
	FOREIGN KEY(vulnerability_id) REFERENCES vulnerabilities (id), 
	FOREIGN KEY(service_id) REFERENCES asset_services (id), 
	FOREIGN KEY(assignee_id) REFERENCES users (id)
);

CREATE INDEX ix_findings_asset_id ON findings (asset_id);
CREATE INDEX ix_findings_project_id ON findings (project_id);

CREATE TABLE scan_results (
	id SERIAL NOT NULL, 
	job_id INTEGER NOT NULL, 
	raw TEXT, 
	parsed_count INTEGER, 
	created_at TIMESTAMP WITH TIME ZONE, 
	PRIMARY KEY (id), 
	FOREIGN KEY(job_id) REFERENCES scan_jobs (id)
);

CREATE INDEX ix_scan_results_job_id ON scan_results (job_id);

CREATE TABLE attack_path_edges (
	id SERIAL NOT NULL, 
	path_id INTEGER NOT NULL, 
	position INTEGER NOT NULL, 
	from_asset_id INTEGER NOT NULL, 
	to_asset_id INTEGER NOT NULL, 
	relation VARCHAR(30) NOT NULL, 
	reason VARCHAR(500), 
	finding_id INTEGER, 
	PRIMARY KEY (id), 
	FOREIGN KEY(path_id) REFERENCES attack_paths (id), 
	FOREIGN KEY(from_asset_id) REFERENCES assets (id), 
	FOREIGN KEY(to_asset_id) REFERENCES assets (id), 
	FOREIGN KEY(finding_id) REFERENCES findings (id)
);

CREATE INDEX ix_attack_path_edges_path_id ON attack_path_edges (path_id);

CREATE TABLE finding_evidence (
	id SERIAL NOT NULL, 
	finding_id INTEGER NOT NULL, 
	tool VARCHAR(16), 
	content TEXT, 
	created_at TIMESTAMP WITH TIME ZONE, 
	PRIMARY KEY (id), 
	FOREIGN KEY(finding_id) REFERENCES findings (id)
);

CREATE INDEX ix_finding_evidence_finding_id ON finding_evidence (finding_id);

CREATE TABLE finding_status_history (
	id SERIAL NOT NULL, 
	finding_id INTEGER NOT NULL, 
	old_status VARCHAR(16), 
	new_status VARCHAR(16) NOT NULL, 
	user_id INTEGER, 
	note VARCHAR(500), 
	created_at TIMESTAMP WITH TIME ZONE, 
	PRIMARY KEY (id), 
	FOREIGN KEY(finding_id) REFERENCES findings (id), 
	FOREIGN KEY(user_id) REFERENCES users (id)
);

CREATE INDEX ix_finding_status_history_finding_id ON finding_status_history (finding_id);

