"""Core Pydantic models and enums for Wardline findings and scans."""

from __future__ import annotations

import hashlib
from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field, field_validator, model_validator

EVIDENCE_MAX_BYTES = 4096


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Category(StrEnum):
    HARDENING = "hardening"
    VULNERABILITY = "vulnerability"
    MALWARE = "malware"
    ROOTKIT = "rootkit"
    INTEGRITY = "integrity"
    NETWORK = "network"
    COMPLIANCE = "compliance"
    PATCHING = "patching"
    PERSISTENCE = "persistence"


class Verdict(StrEnum):
    CONFIRMED = "confirmed"
    LIKELY_FALSE_POSITIVE = "likely_false_positive"
    NEEDS_REVIEW = "needs_review"
    NONE = "none"


class FindingStatus(StrEnum):
    OPEN = "open"
    ACCEPTED_RISK = "accepted_risk"
    RESOLVED = "resolved"


class PluginStatus(StrEnum):
    OK = "ok"
    FINDINGS = "findings"
    SKIPPED = "skipped"
    UNAVAILABLE = "unavailable"
    FAILED = "failed"
    TIMED_OUT = "timed_out"


class BackendKind(StrEnum):
    LOCAL = "local"
    DOCKER = "docker"
    SSH = "ssh"


def make_finding_id(plugin: str, rule_id: str, location: str) -> str:
    """Stable id so the same issue matches across scans (needed for diff)."""
    payload = f"{plugin}\0{rule_id}\0{location}".encode()
    return hashlib.sha256(payload).hexdigest()[:32]


def truncate_evidence(text: str, max_bytes: int = EVIDENCE_MAX_BYTES) -> str:
    """Truncate evidence to max_bytes without splitting a trailing UTF-8 char."""
    raw = text.encode("utf-8")
    if len(raw) <= max_bytes:
        return text
    clipped = raw[:max_bytes]
    while clipped:
        try:
            return clipped.decode("utf-8") + "…"
        except UnicodeDecodeError:
            clipped = clipped[:-1]
    return "…"


class Finding(BaseModel):
    id: str = ""
    scan_id: str
    host: str
    plugin: str
    rule_id: str
    category: Category
    severity: Severity
    title: str
    description: str = ""
    location: str = ""
    evidence: str = ""
    cve_ids: list[str] = Field(default_factory=list)
    fix_hint: str = ""
    references: list[str] = Field(default_factory=list)
    verdict: Verdict = Verdict.NONE
    verdict_reason: str = ""
    related: list[str] = Field(default_factory=list)
    status: FindingStatus = FindingStatus.OPEN
    user_note: str = ""

    @field_validator("evidence", mode="before")
    @classmethod
    def _truncate_evidence(cls, value: object) -> object:
        if isinstance(value, str):
            return truncate_evidence(value)
        return value

    @model_validator(mode="after")
    def _ensure_id(self) -> Finding:
        if not self.id:
            self.id = make_finding_id(self.plugin, self.rule_id, self.location)
        return self


class HostInfo(BaseModel):
    hostname: str
    distro: str = ""
    version: str = ""
    kernel: str = ""
    arch: str = ""
    ram_mb: int | None = None
    is_root: bool = False


class PluginResult(BaseModel):
    plugin: str
    tool_version: str | None = None
    status: PluginStatus
    duration_seconds: float | None = None
    exit_code: int | None = None
    skip_reason: str | None = None
    raw_output_path: str | None = None
    extras: dict[str, Any] = Field(default_factory=dict)


class SeverityCounts(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0

    def total(self) -> int:
        return self.critical + self.high + self.medium + self.low + self.info


class CategoryCounts(BaseModel):
    hardening: int = 0
    vulnerability: int = 0
    malware: int = 0
    rootkit: int = 0
    integrity: int = 0
    network: int = 0
    compliance: int = 0
    patching: int = 0
    persistence: int = 0


class ScanSummary(BaseModel):
    """Headline counts exclude likely_false_positive findings."""

    by_severity: SeverityCounts = Field(default_factory=SeverityCounts)
    by_category: CategoryCounts = Field(default_factory=CategoryCounts)
    total_findings: int = 0
    open_findings: int = 0
    likely_false_positives: int = 0


class ScanScores(BaseModel):
    posture: int = 100
    lynis_hardening_index: int | None = None


class Scan(BaseModel):
    id: str
    wardline_version: str
    started_at: datetime
    finished_at: datetime | None = None
    profile: str
    backend: BackendKind
    host: HostInfo
    plugin_results: list[PluginResult] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    summary: ScanSummary = Field(default_factory=ScanSummary)
    scores: ScanScores = Field(default_factory=ScanScores)
    tags: list[str] = Field(default_factory=list)
