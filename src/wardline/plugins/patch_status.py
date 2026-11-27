"""Pending security patches / reboot / restarted-services status."""

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

_SVC_RE = re.compile(r"^NEEDRESTART-SVC:\s*(?P<svc>\S+)\s*$", re.M)
_DNF_SEC = re.compile(r"^(?P<id>\S+)\s+security\s+(?P<sev>\S+)\s+(?P<pkg>\S+)\s*$", re.M)


class PatchStatusPlugin(Plugin):
    name = "patch_status"
    display_name = "Patch status"
    category = Category.PATCHING
    description = "Pending security updates and services needing restart."
    needs_root = False
    default_timeout = 300.0
    capabilities = default_capabilities(
        docker=CapabilityLevel.PARTIAL,
        notes={BackendKind.DOCKER: "partial"},
    )

    async def detect(self, backend: Backend) -> DetectResult:
        for binary in ("needrestart", "needs-restarting", "dnf", "pro"):
            path = await backend.which(binary)
            if path:
                return DetectResult(installed=True, version=binary, path=path, detail=binary)
        # reboot-required file alone still counts as useful signal on Debian.
        if await backend.exists("/var/run/reboot-required"):
            return DetectResult(installed=True, version="reboot-required", detail="file")
        return DetectResult(installed=False)

    def install_hint(self, distro: DistroInfo) -> list[str]:
        if distro.is_debian_family:
            return ["sudo apt update && sudo apt install -y needrestart"]
        if distro.is_rhel_family:
            return ["sudo dnf install -y dnf-utils"]  # provides needs-restarting
        return ["# install needrestart or dnf-utils"]

    def build_commands(
        self, backend: Backend, options: dict[str, Any] | None = None
    ) -> list[list[str]]:
        options = options or {}
        mode = str(options.get("mode") or "auto")
        cmds: list[list[str]] = []
        if mode in {"auto", "debian", "needrestart"}:
            cmds.append(["needrestart", "-r", "l", "-b"])
        if mode in {"auto", "rhel", "dnf"}:
            cmds.append(["needs-restarting", "-r"])
            cmds.append(["needs-restarting", "-s"])
            cmds.append(["dnf", "updateinfo", "list", "--security"])
        # Always try reboot-required marker via a portable test.
        cmds.append(["sh", "-c", "test -f /var/run/reboot-required; echo REBOOT_REQUIRED:$?"])
        del backend
        return cmds

    def interpret_exit_code(self, code: int) -> PluginStatus:
        # needs-restarting -r returns 1 when reboot needed — still success for us.
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

        if "REBOOT_REQUIRED:0" in raw_output or re.search(
            r"(?m)^Reboot is required|^needs-restarting:.*reboot", raw_output, re.I
        ):
            findings.append(
                Finding(
                    scan_id=scan_id,
                    host=host,
                    plugin=self.name,
                    rule_id="PATCH-REBOOT",
                    category=Category.PATCHING,
                    severity=Severity.HIGH,
                    title="Reboot required",
                    description="System indicates a reboot is needed to activate updates.",
                    location="reboot",
                    evidence="reboot required",
                    fix_hint="Schedule a reboot in a maintenance window.",
                )
            )

        for match in _SVC_RE.finditer(raw_output):
            svc = match.group("svc")
            findings.append(
                Finding(
                    scan_id=scan_id,
                    host=host,
                    plugin=self.name,
                    rule_id=f"PATCH-SVC-{svc}",
                    category=Category.PATCHING,
                    severity=Severity.MEDIUM,
                    title=f"Service running outdated binaries: {svc}",
                    description="needrestart reports this service should be restarted.",
                    location=svc,
                    evidence=match.group(0),
                    fix_hint=f"Restart {svc} after reviewing impact.",
                )
            )

        for match in _DNF_SEC.finditer(raw_output):
            sev_raw = match.group("sev").lower()
            severity = Severity.CRITICAL if "crit" in sev_raw else Severity.HIGH
            if "important" in sev_raw or "moderat" in sev_raw:
                severity = Severity.HIGH if "important" in sev_raw else Severity.MEDIUM
            findings.append(
                Finding(
                    scan_id=scan_id,
                    host=host,
                    plugin=self.name,
                    rule_id=f"PATCH-DNF-{match.group('id')}",
                    category=Category.PATCHING,
                    severity=severity,
                    title=f"Pending security update: {match.group('pkg')}",
                    description=match.group(0),
                    location=match.group("pkg"),
                    evidence=match.group(0),
                    fix_hint="Apply security updates with your package manager.",
                )
            )
        return ParseResult(findings=findings)
