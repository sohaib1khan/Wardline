"""Lynis system audit plugin."""

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

LYNIS_REPORT = "/var/log/lynis-report.dat"

# Suggestions that should be medium (not low).
IMPORTANT_SUGGESTIONS = frozenset(
    {
        "SSH-7408",
        "AUTH-9282",
        "AUTH-9308",
        "PKGS-7392",
        "FIRE-4512",
        "FILE-6310",
    }
)

_WARNING_RE = re.compile(
    r"^warning\[\]=(?P<id>[A-Z0-9-]+)(?:\|(?P<rest>.*))?$",
    re.MULTILINE,
)
_SUGGEST_RE = re.compile(
    r"^suggestion\[\]=(?P<id>[A-Z0-9-]+)(?:\|(?P<rest>.*))?$",
    re.MULTILINE,
)
_INDEX_RE = re.compile(r"^hardening_index=(?P<idx>\d+)\s*$", re.MULTILINE)
_VERSION_RE = re.compile(r"(?i)lynis\s+(\d+\.\d+(?:\.\d+)?)")


class LynisPlugin(Plugin):
    name = "lynis"
    display_name = "Lynis"
    category = Category.HARDENING
    description = "CISOfy Lynis system hardening audit."
    needs_root = True
    default_timeout = 600.0
    needs_network = False
    capabilities = default_capabilities(
        docker=CapabilityLevel.PARTIAL,
        notes={
            BackendKind.DOCKER: "partial — verify Lynis rootdir /host support",
        },
    )

    async def detect(self, backend: Backend) -> DetectResult:
        path = await backend.which("lynis")
        if not path:
            return DetectResult(installed=False)
        version = None
        for argv in (["lynis", "--version"], ["lynis", "show", "version"]):
            result = await backend.run(argv, timeout=15.0)
            text = f"{result.stdout}\n{result.stderr}"
            match = _VERSION_RE.search(text)
            if match:
                version = match.group(1)
                break
            if result.exit_code == 0 and result.stdout.strip():
                version = result.stdout.strip().splitlines()[0][:40]
                break
        return DetectResult(installed=True, version=version, path=path)

    def install_hint(self, distro: DistroInfo) -> list[str]:
        if distro.is_debian_family:
            return [
                "sudo apt update && sudo apt install -y lynis",
                "# For the latest Lynis, use the CISOfy apt repository: https://packages.cisofy.com/",
            ]
        if distro.is_rhel_family:
            return ["sudo dnf install -y lynis"]
        return ["# install lynis from your distro or https://cisofy.com/lynis/"]

    def build_commands(
        self, backend: Backend, options: dict[str, Any] | None = None
    ) -> list[list[str]]:
        del backend, options
        return [["lynis", "audit", "system", "--cronjob", "--quiet"]]

    async def collect_raw_output(self, backend: Backend, results: list[CommandResult]) -> str:
        parts: list[str] = []
        for result in results:
            if result.stdout:
                parts.append(result.stdout)
            if result.stderr:
                parts.append(result.stderr)
        report_path = backend.path(LYNIS_REPORT)
        try:
            raw = await backend.read_file(report_path)
            parts.append(raw.decode("utf-8", errors="replace"))
        except FileNotFoundError:
            parts.append(f"# wardline: missing report file {report_path}")
        except OSError as exc:
            parts.append(f"# wardline: could not read {report_path}: {exc}")
        return "\n".join(parts).strip()

    def interpret_exit_code(self, code: int) -> PluginStatus:
        # Lynis returns non-zero when warnings exist on some versions; treat
        # 0/1 as success-with-possible-findings, higher as failure.
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
        extras: dict[str, Any] = {}

        index_match = _INDEX_RE.search(raw_output)
        if index_match:
            extras["hardening_index"] = int(index_match.group("idx"))

        if re.search(r"(?i)more than \d+ months old|consider upgrading", raw_output):
            findings.append(
                Finding(
                    scan_id=scan_id,
                    host=host,
                    plugin=self.name,
                    rule_id="LYNIS-OUTDATED",
                    category=Category.HARDENING,
                    severity=Severity.INFO,
                    title="Lynis package appears outdated",
                    description="Lynis reported that this release is old.",
                    location="lynis",
                    evidence="outdated warning present in output",
                    fix_hint="Install Lynis from the CISOfy repository for the latest release.",
                    references=["https://packages.cisofy.com/"],
                )
            )

        if "missing report file" in raw_output:
            findings.append(
                Finding(
                    scan_id=scan_id,
                    host=host,
                    plugin=self.name,
                    rule_id="LYNIS-NO-REPORT",
                    category=Category.HARDENING,
                    severity=Severity.MEDIUM,
                    title="Lynis report file not found",
                    description=f"Expected report at {LYNIS_REPORT} after the audit.",
                    location=LYNIS_REPORT,
                    fix_hint="Re-run Lynis as root and confirm it can write the report file.",
                )
            )

        for match in _WARNING_RE.finditer(raw_output):
            rule_id = match.group("id")
            rest = match.group("rest") or ""
            title = rest.split("|", 1)[0].strip() if rest else f"Lynis warning {rule_id}"
            findings.append(
                Finding(
                    scan_id=scan_id,
                    host=host,
                    plugin=self.name,
                    rule_id=rule_id,
                    category=Category.HARDENING,
                    severity=Severity.MEDIUM,
                    title=title or f"Lynis warning {rule_id}",
                    description=rest.replace("|", " — ") if rest else "",
                    location=rule_id,
                    evidence=match.group(0)[:500],
                    fix_hint="Review the Lynis finding and apply the suggested hardening change.",
                )
            )

        for match in _SUGGEST_RE.finditer(raw_output):
            rule_id = match.group("id")
            rest = match.group("rest") or ""
            title = rest.split("|", 1)[0].strip() if rest else f"Lynis suggestion {rule_id}"
            severity = Severity.MEDIUM if rule_id in IMPORTANT_SUGGESTIONS else Severity.LOW
            findings.append(
                Finding(
                    scan_id=scan_id,
                    host=host,
                    plugin=self.name,
                    rule_id=rule_id,
                    category=Category.HARDENING,
                    severity=severity,
                    title=title or f"Lynis suggestion {rule_id}",
                    description=rest.replace("|", " — ") if rest else "",
                    location=rule_id,
                    evidence=match.group(0)[:500],
                    fix_hint="Review the Lynis suggestion and apply if appropriate for this host.",
                )
            )

        return ParseResult(findings=findings, extras=extras)
