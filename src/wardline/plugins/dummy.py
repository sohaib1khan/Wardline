"""Hidden dummy plugin used for runner/registry tests (not a real scanner)."""

from __future__ import annotations

from typing import Any

from wardline.backends.base import Backend
from wardline.core.distro import DistroInfo
from wardline.core.models import Category, Finding, PluginStatus, Severity
from wardline.plugins.base import DetectResult, ParseResult, Plugin


class DummyPlugin(Plugin):
    name = "dummy"
    display_name = "Dummy (dev)"
    category = Category.HARDENING
    description = "Internal test plugin that runs `true` / echoes a line."
    needs_root = False
    default_timeout = 30.0
    hidden = True

    async def detect(self, backend: Backend) -> DetectResult:
        path = await backend.which("true")
        return DetectResult(
            installed=path is not None,
            version="0.0.0",
            path=path,
            detail="always-available POSIX true" if path else "true not found",
        )

    def install_hint(self, distro: DistroInfo) -> list[str]:
        del distro
        return ["# `true` is part of coreutils; nothing to install"]

    def build_commands(
        self, backend: Backend, options: dict[str, Any] | None = None
    ) -> list[list[str]]:
        del backend
        options = options or {}
        mode = str(options.get("mode", "ok"))
        if mode == "fail":
            return [["false"]]
        if mode == "echo":
            return [["printf", "%s\\n", "dummy-ok"]]
        if mode == "sleep":
            seconds = str(options.get("seconds", "30"))
            return [["sleep", seconds]]
        return [["true"]]

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
        if "dummy-ok" in raw_output:
            findings.append(
                Finding(
                    scan_id=scan_id,
                    host=host,
                    plugin=self.name,
                    rule_id="DUMMY-001",
                    category=self.category,
                    severity=Severity.INFO,
                    title="Dummy plugin ran successfully",
                    description="Internal self-check finding from the dummy plugin.",
                    location="dummy",
                    evidence=raw_output[:200],
                )
            )
        return ParseResult(findings=findings, extras={"exit_code": exit_code})

    def interpret_exit_code(self, code: int) -> PluginStatus:
        if code == 0:
            return PluginStatus.OK
        return PluginStatus.FAILED
