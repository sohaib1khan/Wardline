"""ClamAV malware scan plugin."""

from __future__ import annotations

import hashlib
import re
from typing import Any

from wardline.backends.base import Backend
from wardline.core.distro import DistroInfo
from wardline.core.models import Category, Finding, PluginStatus, Severity
from wardline.plugins.base import DetectResult, ParseResult, Plugin, default_capabilities

_FOUND_RE = re.compile(r"^(?P<path>.+):\s+(?P<sig>\S+)\s+FOUND\s*$")


class ClamAVPlugin(Plugin):
    name = "clamav"
    display_name = "ClamAV"
    category = Category.MALWARE
    description = "ClamAV recursive malware scan of configured paths."
    needs_root = False
    min_ram_mb = 4096
    default_timeout = 3600.0
    capabilities = default_capabilities()

    async def detect(self, backend: Backend) -> DetectResult:
        path = await backend.which("clamscan")
        if not path:
            # clamdscan alone is not enough for detect=installed without clamscan binary usually
            alt = await backend.which("clamdscan")
            if not alt:
                return DetectResult(installed=False)
            return DetectResult(
                installed=True, version="clamdscan", path=alt, detail="clamdscan only"
            )
        version = None
        result = await backend.run(["clamscan", "--version"], timeout=15.0)
        text = f"{result.stdout}\n{result.stderr}"
        match = re.search(r"ClamAV\s+(\S+)", text)
        if match:
            version = match.group(1).rstrip("/")
        return DetectResult(installed=True, version=version, path=path)

    def install_hint(self, distro: DistroInfo) -> list[str]:
        if distro.is_debian_family:
            return ["sudo apt update && sudo apt install -y clamav clamav-daemon"]
        if distro.is_rhel_family:
            return ["sudo dnf install -y clamav clamd"]
        return ["# install clamav from your distro packages"]

    def build_commands(
        self, backend: Backend, options: dict[str, Any] | None = None
    ) -> list[list[str]]:
        options = options or {}
        paths = [backend.path(p) for p in (options.get("paths") or ["/home", "/var/www", "/tmp"])]
        # Prefer clamscan; callers may set use_clamd=True when clamd is up.
        binary = "clamdscan" if options.get("use_clamd") else "clamscan"
        # Exclude host virtual filesystems when scanning under /host.
        exclude = "^/(proc|sys|dev|run)|^/host/(proc|sys|dev|run)"
        cmd = [
            binary,
            "-r",
            "-i",
            f"--exclude-dir={exclude}",
            *paths,
        ]
        # --no-summary is supported by clamscan; skip for clamdscan variants that lack it.
        if binary == "clamscan":
            cmd.insert(3, "--no-summary")
        return [cmd]

    def interpret_exit_code(self, code: int) -> PluginStatus:
        # 0 clean, 1 found, 2 error
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
        del options
        findings: list[Finding] = []
        if exit_code == 2:
            findings.append(
                Finding(
                    scan_id=scan_id,
                    host=host,
                    plugin=self.name,
                    rule_id="CLAMAV-ERROR",
                    category=Category.MALWARE,
                    severity=Severity.MEDIUM,
                    title="ClamAV scan error",
                    description="clamscan exited with code 2 (error).",
                    location="clamav",
                    evidence=raw_output[:500],
                    fix_hint="Check signature databases (freshclam) and path permissions.",
                )
            )

        for line in raw_output.splitlines():
            match = _FOUND_RE.match(line.strip())
            if not match:
                continue
            path = match.group("path")
            sig = match.group("sig")
            sha = _safe_sha256_label(path)
            findings.append(
                Finding(
                    scan_id=scan_id,
                    host=host,
                    plugin=self.name,
                    rule_id=f"CLAMAV-{sig}",
                    category=Category.MALWARE,
                    severity=Severity.CRITICAL,
                    title=f"Malware detected: {sig}",
                    description=f"ClamAV reported {sig} at {path}.",
                    location=path,
                    evidence=line[:500],
                    fix_hint=(
                        "Do not delete via Wardline. Isolate the host, inspect the file, "
                        "and consider copying it to the Evidence Locker. "
                        "On SELinux hosts: setsebool -P antivirus_can_scan_system 1 "
                        "(if that boolean exists)."
                    ),
                    references=[],
                    user_note=sha,
                )
            )
        return ParseResult(findings=findings, extras={"exit_code": exit_code})


def _safe_sha256_label(path: str) -> str:
    """Placeholder hash label — real hashing happens when Evidence Locker copies."""
    return "sha256:" + hashlib.sha256(path.encode()).hexdigest()[:16]
