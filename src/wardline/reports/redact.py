"""Redact sensitive values from scans / report text for safe sharing."""

from __future__ import annotations

import copy
import re
from typing import Any

from wardline.core.models import Scan

_IPV4 = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)
# Require compressed form or a full 8-hextet address — avoid matching HH:MM:SS.
_IPV6 = re.compile(
    r"\b(?:(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|"
    r":(?::[0-9a-fA-F]{1,4}){1,7}|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4})\b"
)
_HOME = re.compile(r"(?P<prefix>/home/)(?P<user>[^/\s]+)")
_USER_AT = re.compile(r"\b([a-z_][a-z0-9_-]{0,31})@([A-Za-z0-9.-]+)\b")

_SKIP_KEYS = frozenset(
    {
        "id",
        "scan_id",
        "started_at",
        "finished_at",
        "wardline_version",
        "profile",
        "backend",
        "status",
        "severity",
        "category",
        "verdict",
        "plugin",
        "rule_id",
        "duration_seconds",
        "exit_code",
        "posture",
        "lynis_hardening_index",
        "critical",
        "high",
        "medium",
        "low",
        "info",
        "total_findings",
        "open_findings",
        "likely_false_positives",
        "ram_mb",
        "is_root",
        "arch",
        "kernel",
        "version",
        "distro",
    }
)


def redact_text(text: str, *, hostname: str | None = None) -> str:
    """Mask IPs, home paths, user@host, and optional hostname."""
    out = _IPV4.sub("x.x.x.x", text)
    out = _IPV6.sub("x:x:x:x::x", out)
    out = _HOME.sub(r"\g<prefix>REDACTED", out)
    out = _USER_AT.sub(r"user@\2", out)
    if hostname:
        out = out.replace(hostname, "REDACTED-HOST")
    return out


def redact_scan(scan: Scan) -> Scan:
    """Return a deep-copied Scan with sensitive fields masked."""
    data: dict[str, Any] = copy.deepcopy(scan.model_dump(mode="json"))
    host_name = data.get("host", {}).get("hostname")
    data = _walk(data, hostname=host_name)
    if "host" in data and isinstance(data["host"], dict):
        data["host"]["hostname"] = "REDACTED-HOST"
    return Scan.model_validate(data)


def _walk(value: Any, *, hostname: str | None) -> Any:
    if isinstance(value, str):
        return redact_text(value, hostname=hostname)
    if isinstance(value, list):
        return [_walk(v, hostname=hostname) for v in value]
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for key, item in value.items():
            if key in _SKIP_KEYS:
                out[key] = item
            else:
                out[key] = _walk(item, hostname=hostname)
        return out
    return value
