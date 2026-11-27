"""rkhunter rootkit / file integrity warning plugin."""

from __future__ import annotations

import re
from typing import Any

from wardline.backends.base import Backend, CommandResult
from wardline.core.distro import DistroInfo
from wardline.core.models import BackendKind, Category, Finding, PluginStatus, Severity
from wardline.plugins.base import (
    CapabilityLevel,
    DetectResult,
    ParseResult,
    Plugin,
    default_capabilities,
)

RKHUNTER_LOG = "/var/log/rkhunter.log"
_WARN_RE = re.compile(r"(?im)^Warning:\s*(?P<body>.+)$")
_NOISY = re.compile(r"PermitRootLogin|SSH configuration option", re.I)


class RkhunterPlugin(Plugin):
    name = "rkhunter"
    display_name = "rkhunter"
    category = Category.ROOTKIT
    description = "Rootkit Hunter checks and file property warnings."
    needs_root = True
    default_timeout = 900.0
    capabilities = default_capabilities(
        docker=CapabilityLevel.PARTIAL,
        notes={BackendKind.DOCKER: "verify usefulness in container"},
    )

    async def detect(self, backend: Backend) -> DetectResult:
        path = await backend.which("rkhunter")
        if not path:
            return DetectResult(installed=False)
        result = await backend.run(["rkhunter", "--version"], timeout=15.0)
        text = f"{result.stdout}\n{result.stderr}"
        match = re.search(r"Rootkit Hunter\s+(\d+\.\d+\.\d+)", text)
        version = match.group(1) if match else None
        return DetectResult(installed=True, version=version, path=path)

    def install_hint(self, distro: DistroInfo) -> list[str]:
        if distro.is_debian_family:
            return ["sudo apt update && sudo apt install -y rkhunter"]
        if distro.is_rhel_family:
            return ["sudo dnf install -y rkhunter"]
        return ["# install rkhunter from your distro"]

    def build_commands(
        self, backend: Backend, options: dict[str, Any] | None = None
    ) -> list[list[str]]:
        del backend, options
        # --sk skip keypress, --rwo report warnings only, --nocolors
        return [["rkhunter", "--check", "--sk", "--rwo", "--nocolors"]]

    async def collect_raw_output(self, backend: Backend, results: list[CommandResult]) -> str:
        parts: list[str] = []
        for result in results:
            if result.stdout:
                parts.append(result.stdout)
            if result.stderr:
                parts.append(result.stderr)
        log_path = backend.path(RKHUNTER_LOG)
        try:
            raw = await backend.read_file(log_path)
            parts.append(raw.decode("utf-8", errors="replace"))
        except (FileNotFoundError, OSError):
            parts.append(f"# wardline: could not read {log_path}")
        return "\n".join(parts).strip()

    def interpret_exit_code(self, code: int) -> PluginStatus:
        # Non-zero often means warnings found.
        if code in {0, 1}:
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
        del exit_code, options
        findings: list[Finding] = []
        if re.search(r"Invalid WEB_CMD|WEB_CMD configuration", raw_output, re.I):
            findings.append(
                Finding(
                    scan_id=scan_id,
                    host=host,
                    plugin=self.name,
                    rule_id="RKH-WEB-CMD",
                    category=Category.ROOTKIT,
                    severity=Severity.LOW,
                    title="rkhunter WEB_CMD / mirror quirk",
                    description="Debian/Ubuntu WEB_CMD configuration issue detected.",
                    location="/etc/rkhunter.conf",
                    evidence="WEB_CMD configuration",
                    fix_hint="Set WEB_CMD to a working value in /etc/rkhunter.conf (or disable).",
                )
            )

        for match in _WARN_RE.finditer(raw_output):
            body = match.group("body").strip()
            severity = Severity.LOW if _NOISY.search(body) else Severity.MEDIUM
            rule = (
                "RKH-FILE-CHANGED" if "file properties have changed" in body.lower() else "RKH-WARN"
            )
            # Capture following "File: /path" lines for correlation (R2).
            start = match.end()
            tail = raw_output[start : start + 400]
            file_match = re.search(r"(?m)^\s*File:\s*(?P<path>/\S+)\s*$", tail)
            location = file_match.group("path") if file_match else "rkhunter"
            evidence = match.group(0)
            if file_match:
                evidence = f"{evidence}\n         File: {location}"
            findings.append(
                Finding(
                    scan_id=scan_id,
                    host=host,
                    plugin=self.name,
                    rule_id=rule,
                    category=Category.ROOTKIT if rule != "RKH-FILE-CHANGED" else Category.INTEGRITY,
                    severity=severity,
                    title=body[:120],
                    description=body,
                    location=location,
                    evidence=evidence[:500],
                    fix_hint=(
                        "Investigate changed files with package verification before any "
                        "rkhunter --propupd (use Wardline Guarded Baseline)."
                        if rule == "RKH-FILE-CHANGED"
                        else "Review the rkhunter warning and apply the suggested config fix."
                    ),
                )
            )
        return ParseResult(findings=findings)
