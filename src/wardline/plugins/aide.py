"""AIDE integrity check plugin."""

from __future__ import annotations

import re
from typing import Any

from wardline.backends.base import Backend
from wardline.core.distro import DistroInfo
from wardline.core.models import BackendKind, Category, Finding, PluginStatus, Severity
from wardline.plugins.base import (
    CapabilityLevel,
    DetectResult,
    ParseResult,
    Plugin,
    default_capabilities,
)

_BIN_DIRS = ("/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/")
_SENSITIVE = ("/etc/passwd", "/etc/shadow", "/etc/sudoers")
_ENTRY_LINE = re.compile(r"(?m)^(?P<kind>f)(?P<flags>[^\s:]*)\s*:\s*(?P<path>\S+)\s*$")


class AidePlugin(Plugin):
    name = "aide"
    display_name = "AIDE"
    category = Category.INTEGRITY
    description = "AIDE filesystem integrity check against the local baseline."
    needs_root = True
    default_timeout = 1800.0
    capabilities = default_capabilities(
        docker=CapabilityLevel.PARTIAL,
        notes={BackendKind.DOCKER: "partial — root_prefix / verify"},
    )

    async def detect(self, backend: Backend) -> DetectResult:
        path = await backend.which("aide")
        if not path:
            return DetectResult(installed=False)
        result = await backend.run(["aide", "--version"], timeout=15.0)
        text = f"{result.stdout}\n{result.stderr}"
        match = re.search(r"Aide\s+(\d+\.\d+(?:\.\d+)?)", text, re.I)
        version = match.group(1) if match else None
        return DetectResult(installed=True, version=version, path=path)

    def install_hint(self, distro: DistroInfo) -> list[str]:
        if distro.is_debian_family:
            return ["sudo apt update && sudo apt install -y aide aide-common"]
        if distro.is_rhel_family:
            return [
                "sudo dnf install -y aide",
                "# On RHEL 9.8+/AIDE 0.19, run aide-migrate-config if upgrading from 0.16",
            ]
        return ["# install aide from your distro"]

    def build_commands(
        self, backend: Backend, options: dict[str, Any] | None = None
    ) -> list[list[str]]:
        options = options or {}
        # Ubuntu/Debian typically need an explicit config path.
        config = options.get("config")
        if config:
            return [["aide", "--config", str(config), "--check"]]
        # Prefer Debian path when present; otherwise default aide --check.
        # Detection of which config exists is async; keep sync command simple.
        del backend
        return [["aide", "--check"]]

    def interpret_exit_code(self, code: int) -> PluginStatus:
        # 0 ok; non-zero usually differences (or error). Treat as OK-with-findings path.
        if code in {0, 1, 2}:
            return PluginStatus.OK
        return PluginStatus.FAILED

    def parse(
        self,
        raw_output: str,
        exit_code: int,
        *,
        scan_id: str,
        host: str,
        options: dict[str, Any] | None = None,
    ) -> ParseResult:
        del options
        findings: list[Finding] = []
        lower = raw_output.lower()
        if (
            "no database" in lower
            or "cannot open database" in lower
            or (
                exit_code != 0
                and "aide" in lower
                and "database" in lower
                and "found differences" not in lower
            )
        ):
            findings.append(
                Finding(
                    scan_id=scan_id,
                    host=host,
                    plugin=self.name,
                    rule_id="AIDE-NO-BASELINE",
                    category=Category.INTEGRITY,
                    severity=Severity.MEDIUM,
                    title="No AIDE baseline",
                    description="AIDE database/baseline appears missing.",
                    location="aide",
                    evidence=raw_output[:400],
                    fix_hint="Initialize via Wardline Guarded Baseline (never blind re-baseline).",
                )
            )

        seen: set[str] = set()
        for match in _ENTRY_LINE.finditer(raw_output):
            path = match.group("path").strip()
            flags = match.group("flags")
            if "+" in flags and "-" not in flags and ">" not in flags:
                kind = "added"
            elif "-" in flags and "+" not in flags and ">" not in flags:
                kind = "removed"
            else:
                kind = "changed"
            findings.append(_finding_for(scan_id, host, self.name, kind, path, match.group(0)))
            seen.add(path)

        for kind, title in (
            ("added", "Added"),
            ("removed", "Removed"),
            ("changed", "Changed"),
        ):
            for path in _paths_from_section(raw_output, title):
                if path in seen:
                    continue
                findings.append(_finding_for(scan_id, host, self.name, kind, path, path))
                seen.add(path)

        return ParseResult(findings=findings, extras={"exit_code": exit_code})


def _paths_from_section(text: str, title: str) -> list[str]:
    # Require a line-start header so we don't match Summary counts like
    # "Changed entries:\t3".
    pattern = re.compile(
        rf"(?ms)^{title} entries:\s*\n-{{5,}}\s*\n(?P<body>.*?)(?=^-{{5,}}|\Z)",
        re.I,
    )
    match = pattern.search(text)
    if not match:
        return []
    paths: list[str] = []
    for line in match.group("body").splitlines():
        line = line.strip()
        if not line or line.startswith("-"):
            continue
        # Formats: "f++++: /path", "f   >.... mc..H..: /path", or bare path
        path = line.split(":", 1)[-1].strip() if ":" in line else line
        if path.startswith("/"):
            paths.append(path.split()[0])
    return paths


def _finding_for(
    scan_id: str, host: str, plugin: str, kind: str, path: str, evidence: str
) -> Finding:
    severity = Severity.MEDIUM
    title = f"AIDE {kind}: {path}"
    if kind == "added" and any(path.startswith(d) for d in _BIN_DIRS) and "/." in path:
        severity = Severity.CRITICAL
        title = f"Hidden new file in bin dir: {path}"
    elif (
        kind == "changed"
        and (
            path in _SENSITIVE
            or path.startswith("/etc/sudoers")
            or any(path.startswith(d) for d in _BIN_DIRS)
        )
    ) or (kind == "removed" and any(path.startswith(d) for d in _BIN_DIRS)):
        severity = Severity.HIGH

    return Finding(
        scan_id=scan_id,
        host=host,
        plugin=plugin,
        rule_id=f"AIDE-{kind.upper()}-{path}",
        category=Category.INTEGRITY,
        severity=severity,
        title=title,
        description=f"AIDE reported {kind} entry at {path}.",
        location=path,
        evidence=evidence[:500],
        fix_hint="Verify with package tools before re-baselining (Guarded Baseline).",
    )
