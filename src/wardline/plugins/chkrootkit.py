"""chkrootkit plugin."""

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

DEFAULT_FALSE_POSITIVES = [
    "/usr/lib/python3/dist-packages/fail2ban/tests/",
]

_INFECTED_RE = re.compile(r"(?i)INFECTED")
_HIDDEN_RE = re.compile(r"(?i)(hidden|/tmp/\.|/\.[A-Za-z0-9_-]+)")


class ChkrootkitPlugin(Plugin):
    name = "chkrootkit"
    display_name = "chkrootkit"
    category = Category.ROOTKIT
    description = "chkrootkit quick rootkit checks."
    needs_root = True
    default_timeout = 600.0
    capabilities = default_capabilities(
        docker=CapabilityLevel.PARTIAL,
        notes={BackendKind.DOCKER: "partial — chkrootkit -r /host (verify)"},
    )

    async def detect(self, backend: Backend) -> DetectResult:
        path = await backend.which("chkrootkit")
        if not path:
            return DetectResult(installed=False)
        result = await backend.run(["chkrootkit", "-V"], timeout=10.0)
        text = f"{result.stdout}\n{result.stderr}"
        match = re.search(r"chkrootkit\s+version\s+(\S+)", text, re.I)
        version = match.group(1) if match else None
        return DetectResult(installed=True, version=version, path=path)

    def install_hint(self, distro: DistroInfo) -> list[str]:
        if distro.is_debian_family:
            return ["sudo apt update && sudo apt install -y chkrootkit"]
        if distro.is_rhel_family:
            return ["sudo dnf install -y chkrootkit"]
        return ["# install chkrootkit from your distro"]

    def build_commands(
        self, backend: Backend, options: dict[str, Any] | None = None
    ) -> list[list[str]]:
        del options
        root = backend.path("/")
        if root != "/":
            return [["chkrootkit", "-q", "-r", root]]
        return [["chkrootkit", "-q"]]

    def interpret_exit_code(self, code: int) -> PluginStatus:
        return PluginStatus.OK if code == 0 else PluginStatus.FAILED

    def parse(
        self,
        raw_output: str,
        exit_code: int,
        *,
        scan_id: str,
        host: str,
        options: dict[str, Any] | None = None,
    ) -> ParseResult:
        del exit_code
        options = options or {}
        fp_prefixes = list(options.get("false_positives") or DEFAULT_FALSE_POSITIVES)
        findings: list[Finding] = []

        for line in raw_output.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            if _INFECTED_RE.search(stripped):
                findings.append(
                    Finding(
                        scan_id=scan_id,
                        host=host,
                        plugin=self.name,
                        rule_id="CHK-INFECTED",
                        category=Category.ROOTKIT,
                        severity=Severity.CRITICAL,
                        title="chkrootkit reported INFECTED",
                        description=stripped,
                        location="chkrootkit",
                        evidence=stripped[:500],
                        fix_hint="Investigate immediately; do not ignore INFECTED results.",
                    )
                )
                continue

            if any(stripped.startswith(prefix) or prefix in stripped for prefix in fp_prefixes):
                continue

            if stripped.startswith("/") and _HIDDEN_RE.search(stripped):
                findings.append(
                    Finding(
                        scan_id=scan_id,
                        host=host,
                        plugin=self.name,
                        rule_id="CHK-HIDDEN",
                        category=Category.ROOTKIT,
                        severity=Severity.LOW,
                        title=f"Suspicious path reported by chkrootkit: {stripped}",
                        description=stripped,
                        location=stripped.split()[0],
                        evidence=stripped[:500],
                        fix_hint=(
                            "Review the path. Add known false positives under "
                            "scan.false_positives.chkrootkit if intentional."
                        ),
                    )
                )
        return ParseResult(findings=findings)
