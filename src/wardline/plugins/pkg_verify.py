"""Package verification via debsums / rpm -V."""

from __future__ import annotations

import re
from typing import Any

from wardline.backends.base import Backend
from wardline.core.distro import DistroInfo
from wardline.core.models import Category, Finding, PluginStatus, Severity
from wardline.plugins.base import DetectResult, ParseResult, Plugin, default_capabilities

_DEBSUMS_FAIL = re.compile(r"^(?P<path>\S+)\s+FAILED\s*$")
_RPM_LINE = re.compile(r"^(?P<flags>[S.\dMSMGTUAP?]{9})\s+(?P<cfg>c\s+)?(?P<path>/\S+)\s*$")


class PkgVerifyPlugin(Plugin):
    name = "pkg_verify"
    display_name = "Package verify"
    category = Category.INTEGRITY
    description = "Verify installed package files (debsums / rpm -Va)."
    needs_root = False
    default_timeout = 300.0
    capabilities = default_capabilities()

    async def detect(self, backend: Backend) -> DetectResult:
        debsums = await backend.which("debsums")
        if debsums:
            return DetectResult(installed=True, version="debsums", path=debsums, detail="debsums")
        rpm = await backend.which("rpm")
        if rpm:
            return DetectResult(installed=True, version="rpm", path=rpm, detail="rpm")
        return DetectResult(installed=False)

    def install_hint(self, distro: DistroInfo) -> list[str]:
        if distro.is_debian_family:
            return ["sudo apt update && sudo apt install -y debsums"]
        if distro.is_rhel_family:
            return ["# rpm is part of the base system on RHEL-family hosts"]
        return ["# install debsums or use rpm -Va"]

    def build_commands(
        self, backend: Backend, options: dict[str, Any] | None = None
    ) -> list[list[str]]:
        options = options or {}
        mode = str(options.get("mode") or "auto")
        files = list(options.get("files") or [])
        del backend
        if mode == "rpm" or (mode == "auto" and options.get("prefer_rpm")):
            if files:
                cmds = []
                for path in files:
                    cmds.append(["rpm", "-Vf", path])
                return cmds
            return [["rpm", "-Va"]]
        # debsums
        if files:
            # debsums -s on owning packages is complex; verify paths via -c style listing.
            return [["debsums", "-s", *files]]
        return [["debsums", "-s"]]

    def interpret_exit_code(self, code: int) -> PluginStatus:
        # debsums returns non-zero when mismatches exist.
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
        del exit_code, options
        findings: list[Finding] = []
        for line in raw_output.splitlines():
            line = line.strip()
            if not line:
                continue
            deb = _DEBSUMS_FAIL.match(line)
            if deb:
                path = deb.group("path")
                is_config = path.startswith("/etc/")
                findings.append(
                    Finding(
                        scan_id=scan_id,
                        host=host,
                        plugin=self.name,
                        rule_id=f"DEBSUMS-{path}",
                        category=Category.INTEGRITY,
                        severity=Severity.MEDIUM if is_config else Severity.CRITICAL,
                        title=f"debsums mismatch: {path}",
                        description="Package checksum verification failed for this path.",
                        location=path,
                        evidence=line,
                        fix_hint="Investigate possible tampering; do not ignore binary mismatches.",
                    )
                )
                continue
            rpm = _RPM_LINE.match(line)
            if rpm:
                flags = rpm.group("flags")
                path = rpm.group("path")
                is_config = bool(rpm.group("cfg")) or path.startswith("/etc/")
                # '5' in rpm verify means MD5/digest mismatch.
                digest_changed = len(flags) > 2 and flags[2] == "5"
                severity = Severity.MEDIUM
                if digest_changed and not is_config:
                    severity = Severity.CRITICAL
                elif digest_changed:
                    severity = Severity.HIGH
                findings.append(
                    Finding(
                        scan_id=scan_id,
                        host=host,
                        plugin=self.name,
                        rule_id=f"RPM-V-{path}",
                        category=Category.INTEGRITY,
                        severity=severity,
                        title=f"rpm verify mismatch: {path}",
                        description=f"rpm -V flags={flags} config={is_config}",
                        location=path,
                        evidence=line,
                        fix_hint="Checksum change on a non-config binary may indicate tampering.",
                    )
                )
        return ParseResult(findings=findings)
