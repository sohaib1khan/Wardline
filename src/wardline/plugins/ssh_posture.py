"""SSH daemon + key posture checks (read-only file inspection)."""

from __future__ import annotations

import json
from typing import Any

from wardline.backends.base import Backend, CommandResult
from wardline.core.distro import DistroInfo
from wardline.core.models import Category, Finding, PluginStatus, Severity
from wardline.core.ssh_inspect import gather_ssh_inspection
from wardline.plugins.base import DetectResult, ParseResult, Plugin, default_capabilities

_SEV = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}


class SshPosturePlugin(Plugin):
    name = "ssh_posture"
    display_name = "SSH Posture"
    category = Category.HARDENING
    description = "Inspect sshd_config hardening and local SSH key permissions."
    needs_root = False
    default_timeout = 60.0
    capabilities = default_capabilities()

    async def detect(self, backend: Backend) -> DetectResult:
        del backend
        return DetectResult(installed=True, version="builtin")

    def install_hint(self, distro: DistroInfo) -> list[str]:
        del distro
        return ["# Built into Wardline — no extra package required"]

    def build_commands(
        self, backend: Backend, options: dict[str, Any] | None = None
    ) -> list[list[str]]:
        del backend, options
        return [["true"]]

    def interpret_exit_code(self, code: int) -> PluginStatus:
        return PluginStatus.OK if code == 0 else PluginStatus.FAILED

    async def collect_raw_output(self, backend: Backend, results: list[CommandResult]) -> str:
        del backend, results
        insp = gather_ssh_inspection()
        return json.dumps(
            {
                "lines": insp.lines,
                "directives": insp.directives,
                "host_keys": insp.host_keys,
                "user_keys": insp.user_keys,
                "auth_keys_count": insp.auth_keys_count,
                "drafts": [
                    {
                        "rule_id": d.rule_id,
                        "severity": d.severity,
                        "title": d.title,
                        "location": d.location,
                        "description": d.description,
                        "fix_hint": d.fix_hint,
                        "evidence": d.evidence,
                    }
                    for d in insp.drafts
                ],
            },
            indent=2,
        )

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
        try:
            data = json.loads(raw_output) if raw_output.strip() else {}
        except json.JSONDecodeError:
            data = {}
        drafts = data.get("drafts") or []
        findings: list[Finding] = []
        for draft in drafts:
            findings.append(
                Finding(
                    scan_id=scan_id,
                    host=host,
                    plugin=self.name,
                    rule_id=str(draft.get("rule_id") or "SSH-UNKNOWN"),
                    category=Category.HARDENING,
                    severity=_SEV.get(str(draft.get("severity") or "info"), Severity.INFO),
                    title=str(draft.get("title") or "SSH finding"),
                    description=str(draft.get("description") or ""),
                    location=str(draft.get("location") or ""),
                    fix_hint=str(draft.get("fix_hint") or ""),
                    evidence=str(draft.get("evidence") or "")[:4000],
                )
            )
        lines = data.get("lines") or []
        if not findings:
            findings.append(
                Finding(
                    scan_id=scan_id,
                    host=host,
                    plugin=self.name,
                    rule_id="SSH-POSTURE-OK",
                    category=Category.HARDENING,
                    severity=Severity.INFO,
                    title="No SSH posture issues flagged",
                    description="sshd directives and local key permissions look reasonable.",
                    location="/etc/ssh/sshd_config",
                    evidence="\n".join(lines)[:4000],
                )
            )
        return ParseResult(
            findings=findings,
            extras={
                "ssh_lines": lines,
                "directives": data.get("directives") or {},
                "auth_keys_count": data.get("auth_keys_count") or 0,
            },
        )
