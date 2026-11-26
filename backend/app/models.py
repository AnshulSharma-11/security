from datetime import datetime, timezone
from sqlalchemy import (JSON, Boolean, Column, DateTime, Float, ForeignKey, Integer, String, Text,
                        UniqueConstraint)
from sqlalchemy.orm import relationship
from .db import Base

SEVERITIES = ["info", "low", "medium", "high", "critical"]
STATUSES = ["open", "confirmed", "false_positive", "accepted_risk", "in_progress", "resolved"]
ROLES = ["admin", "analyst"]


def now():
    return datetime.now(timezone.utc)


def TS(**kw):
    return Column(DateTime(timezone=True), default=now, **kw)


class Organization(Base):
    __tablename__ = "organizations"
    id = Column(Integer, primary_key=True)
    name = Column(String(120), unique=True, nullable=False)
    created_at = TS()


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    email = Column(String(254), unique=True, nullable=False, index=True)
    name = Column(String(120), nullable=False)
    password_hash = Column(String(100), nullable=False)
    role = Column(String(16), nullable=False, default="analyst")  # admin | analyst
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = TS()
    last_login = Column(DateTime(timezone=True))


class Project(Base):
    __tablename__ = "projects"
    __table_args__ = (UniqueConstraint("org_id", "name"),)
    id = Column(Integer, primary_key=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    name = Column(String(120), nullable=False)
    description = Column(Text, default="")
    created_at = TS()


class Asset(Base):
    __tablename__ = "assets"
    __table_args__ = (UniqueConstraint("project_id", "value"),)
    id = Column(Integer, primary_key=True)
    project_id = Column(Integer, ForeignKey("projects.id"), nullable=False, index=True)
    value = Column(String(300), nullable=False)          # what the user typed (normalised)
    asset_type = Column(String(16), nullable=False)      # domain | hostname | ip | url
    hostname = Column(String(253))
    ip = Column(String(45))
    criticality = Column(Integer, default=3, nullable=False)   # 1 (low) .. 5 (crown jewel)
    exposure = Column(String(16), default="unknown", nullable=False)  # internet | internal | unknown
    status = Column(String(16), default="needs_review", nullable=False)  # active | inactive | needs_review
    authorization_status = Column(String(16), default="pending", nullable=False)  # pending | approved | revoked
    authorization_note = Column(Text, default="")
    authorized_by = Column(Integer, ForeignKey("users.id"))
    authorized_at = Column(DateTime(timezone=True))
    dns_info = Column(JSON, default=dict)
    last_seen = Column(DateTime(timezone=True))
    created_by = Column(Integer, ForeignKey("users.id"))
    created_at = TS()
    services = relationship("AssetService", cascade="all, delete-orphan", lazy="selectin")
    technologies = relationship("Technology", cascade="all, delete-orphan", lazy="selectin")


class AssetService(Base):
    __tablename__ = "asset_services"
    __table_args__ = (UniqueConstraint("asset_id", "port", "protocol"),)
    id = Column(Integer, primary_key=True)
    asset_id = Column(Integer, ForeignKey("assets.id"), nullable=False, index=True)
    port = Column(Integer, nullable=False)
    protocol = Column(String(8), default="tcp")
    service = Column(String(60))
    product = Column(String(120))
    version = Column(String(80))
    state = Column(String(12), default="open")
    http_url = Column(String(300))
    http_status = Column(Integer)
    http_title = Column(String(200))
    last_seen = TS()


class Technology(Base):
    __tablename__ = "technologies"
    __table_args__ = (UniqueConstraint("asset_id", "name"),)
    id = Column(Integer, primary_key=True)
    asset_id = Column(Integer, ForeignKey("assets.id"), nullable=False, index=True)
    name = Column(String(80), nullable=False)
    version = Column(String(60))
    source = Column(String(30), default="http-headers")


class AssetLink(Base):
    """Directed relationship used as an edge of the attack graph (src can reach / influence dst)."""
    __tablename__ = "asset_links"
    __table_args__ = (UniqueConstraint("src_id", "dst_id", "relation"),)
    id = Column(Integer, primary_key=True)
    project_id = Column(Integer, ForeignKey("projects.id"), nullable=False, index=True)
    src_id = Column(Integer, ForeignKey("assets.id"), nullable=False)
    dst_id = Column(Integer, ForeignKey("assets.id"), nullable=False)
    relation = Column(String(30), nullable=False)
    note = Column(String(300), default="")
    created_by = Column(Integer, ForeignKey("users.id"))


class Scan(Base):
    __tablename__ = "scans"
    id = Column(Integer, primary_key=True)
    project_id = Column(Integer, ForeignKey("projects.id"), nullable=False, index=True)
    kind = Column(String(16), nullable=False)  # discovery | assessment
    scanners = Column(JSON, default=list)
    status = Column(String(16), default="queued", nullable=False)  # queued running completed failed cancelled
    cancel_requested = Column(Boolean, default=False)
    created_by = Column(Integer, ForeignKey("users.id"))
    created_at = TS()
    started_at = Column(DateTime(timezone=True))
    finished_at = Column(DateTime(timezone=True))
    jobs = relationship("ScanJob", cascade="all, delete-orphan", lazy="selectin", order_by="ScanJob.id")


class ScanJob(Base):
    __tablename__ = "scan_jobs"
    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False, index=True)
    asset_id = Column(Integer, ForeignKey("assets.id"), nullable=False)
    tool = Column(String(16), nullable=False)  # discovery | nmap | nuclei
    status = Column(String(16), default="queued", nullable=False)
    error = Column(Text)
    celery_id = Column(String(60))
    findings_created = Column(Integer, default=0)
    findings_updated = Column(Integer, default=0)
    started_at = Column(DateTime(timezone=True))
    finished_at = Column(DateTime(timezone=True))


class ScanResult(Base):
    __tablename__ = "scan_results"
    id = Column(Integer, primary_key=True)
    job_id = Column(Integer, ForeignKey("scan_jobs.id"), nullable=False, index=True)
    raw = Column(Text)  # truncated raw scanner output, kept for audit; never rendered as HTML
    parsed_count = Column(Integer, default=0)
    created_at = TS()


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"
    id = Column(Integer, primary_key=True)
    key = Column(String(200), unique=True, nullable=False)  # e.g. nuclei:CVE-2021-41773
    title = Column(String(300), nullable=False)
    severity = Column(String(12), nullable=False)
    cvss = Column(Float)
    cve = Column(String(40))
    description = Column(Text, default="")
    remediation = Column(Text, default="")
    references = Column(JSON, default=list)
    tags = Column(JSON, default=list)
    exploit_known = Column(Boolean, default=False)


class Finding(Base):
    __tablename__ = "findings"
    __table_args__ = (UniqueConstraint("project_id", "dedup_key"),)
    id = Column(Integer, primary_key=True)
    project_id = Column(Integer, ForeignKey("projects.id"), nullable=False, index=True)
    asset_id = Column(Integer, ForeignKey("assets.id"), nullable=False, index=True)
    vulnerability_id = Column(Integer, ForeignKey("vulnerabilities.id"), nullable=False)
    service_id = Column(Integer, ForeignKey("asset_services.id"))
    dedup_key = Column(String(64), nullable=False)
    title = Column(String(300), nullable=False)
    severity = Column(String(12), nullable=False)
    status = Column(String(16), default="open", nullable=False)
    assignee_id = Column(Integer, ForeignKey("users.id"))
    source_tool = Column(String(16))
    occurrences = Column(Integer, default=1)
    risk_score = Column(Float, default=0)
    risk_factors = Column(JSON, default=list)
    first_seen = TS()
    last_seen = TS()
    asset = relationship("Asset", lazy="joined")
    vulnerability = relationship("Vulnerability", lazy="joined")
    assignee = relationship("User", lazy="joined")
    service = relationship("AssetService", lazy="joined")


class FindingEvidence(Base):
    __tablename__ = "finding_evidence"
    id = Column(Integer, primary_key=True)
    finding_id = Column(Integer, ForeignKey("findings.id"), nullable=False, index=True)
    tool = Column(String(16))
    content = Column(Text)
    created_at = TS()


class FindingStatusHistory(Base):
    __tablename__ = "finding_status_history"
    id = Column(Integer, primary_key=True)
    finding_id = Column(Integer, ForeignKey("findings.id"), nullable=False, index=True)
    old_status = Column(String(16))
    new_status = Column(String(16), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"))
    note = Column(String(500), default="")
    created_at = TS()


class RiskScore(Base):
    """Project-level risk snapshots used for the dashboard trend."""
    __tablename__ = "risk_scores"
    id = Column(Integer, primary_key=True)
    project_id = Column(Integer, ForeignKey("projects.id"), nullable=False, index=True)
    score = Column(Float, nullable=False)
    detail = Column(JSON, default=dict)
    created_at = TS()


class AttackPath(Base):
    __tablename__ = "attack_paths"
    id = Column(Integer, primary_key=True)
    project_id = Column(Integer, ForeignKey("projects.id"), nullable=False, index=True)
    entry_asset_id = Column(Integer, ForeignKey("assets.id"), nullable=False)
    target_asset_id = Column(Integer, ForeignKey("assets.id"), nullable=False)
    hops = Column(Integer, nullable=False)
    risk_score = Column(Float, nullable=False)
    score_factors = Column(JSON, default=list)
    explanation = Column(Text, default="")
    created_at = TS()
    nodes = relationship("AttackPathNode", cascade="all, delete-orphan", lazy="selectin",
                         order_by="AttackPathNode.position")
    edges = relationship("AttackPathEdge", cascade="all, delete-orphan", lazy="selectin",
                         order_by="AttackPathEdge.position")


class AttackPathNode(Base):
    __tablename__ = "attack_path_nodes"
    id = Column(Integer, primary_key=True)
    path_id = Column(Integer, ForeignKey("attack_paths.id"), nullable=False, index=True)
    position = Column(Integer, nullable=False)
    asset_id = Column(Integer, ForeignKey("assets.id"), nullable=False)
    role = Column(String(10), nullable=False)  # entry | pivot | target
    asset = relationship("Asset", lazy="joined")


class AttackPathEdge(Base):
    __tablename__ = "attack_path_edges"
    id = Column(Integer, primary_key=True)
    path_id = Column(Integer, ForeignKey("attack_paths.id"), nullable=False, index=True)
    position = Column(Integer, nullable=False)
    from_asset_id = Column(Integer, ForeignKey("assets.id"), nullable=False)
    to_asset_id = Column(Integer, ForeignKey("assets.id"), nullable=False)
    relation = Column(String(30), nullable=False)
    reason = Column(String(500), default="")
    finding_id = Column(Integer, ForeignKey("findings.id"))


class AuditLog(Base):
    __tablename__ = "audit_logs"
    id = Column(Integer, primary_key=True)
    org_id = Column(Integer, index=True)
    project_id = Column(Integer, index=True)
    user_id = Column(Integer)
    user_email = Column(String(254))
    action = Column(String(60), nullable=False, index=True)
    target_type = Column(String(30))
    target_id = Column(Integer)
    detail = Column(Text, default="")
    ip_address = Column(String(45))
    created_at = TS()


class Report(Base):
    __tablename__ = "reports"
    id = Column(Integer, primary_key=True)
    project_id = Column(Integer, ForeignKey("projects.id"), nullable=False, index=True)
    kind = Column(String(16), nullable=False)  # executive | technical
    title = Column(String(200))
    content = Column(Text)  # fully escaped HTML
    created_by = Column(Integer, ForeignKey("users.id"))
    created_at = TS()
