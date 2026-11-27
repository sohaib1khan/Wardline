"""Parser and denylist tests for Trivy."""

from __future__ import annotations

from pathlib import Path

import pytest

from wardline.backends.base import CommandResult
from wardline.backends.local import LocalBackend
from wardline.core.models import Severity
from wardline.plugins.base import DetectResult
from wardline.plugins.trivy import TRIVY_DENYLIST, TrivyPlugin

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "trivy"
SCAN_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
HOST = "lab01.example.internal"


def test_trivy_json_parser() -> None:
    raw = (FIXTURES / "rootfs_vulns.json").read_text(encoding="utf-8")
    result = TrivyPlugin().parse(raw, 0, scan_id=SCAN_ID, host=HOST)
    by_id = {f.rule_id: f for f in result.findings}
    assert by_id["CVE-2024-6387"].severity == Severity.HIGH
    assert by_id["CVE-2025-32463"].severity == Severity.CRITICAL
    assert "openssh-server" in by_id["CVE-2024-6387"].location


def test_trivy_toomanyrequests() -> None:
    raw = (FIXTURES / "toomanyrequests.txt").read_text(encoding="utf-8")
    result = TrivyPlugin().parse(raw, 1, scan_id=SCAN_ID, host=HOST)
    assert any(f.rule_id == "TRIVY-TOOMANYREQUESTS" for f in result.findings)


def test_trivy_denylist_findings() -> None:
    findings = TrivyPlugin().denylist_findings(scan_id=SCAN_ID, host=HOST, version="0.69.5")
    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL
    assert "0.69.5" in findings[0].description


def test_trivy_denylist_versions() -> None:
    assert frozenset({"0.69.4", "0.69.5", "0.69.6"}) == TRIVY_DENYLIST
    plugin = TrivyPlugin()
    for ver in TRIVY_DENYLIST:
        assert plugin.check_denylist(ver)


@pytest.mark.asyncio
async def test_trivy_detect_marks_denylisted(monkeypatch: pytest.MonkeyPatch) -> None:
    plugin = TrivyPlugin()
    backend = LocalBackend(apply_priority=False)

    async def fake_which(binary: str) -> str | None:
        return "/usr/bin/trivy" if binary == "trivy" else None

    async def fake_run(cmd, **kwargs):  # type: ignore[no-untyped-def]
        del kwargs
        if cmd[:2] == ["trivy", "--version"]:
            return CommandResult(
                exit_code=0,
                stdout="Version: 0.69.4\n",
                stderr="",
                argv=cmd,
            )
        return CommandResult(exit_code=1, stdout="", stderr="", argv=cmd)

    monkeypatch.setattr(backend, "which", fake_which)
    monkeypatch.setattr(backend, "run", fake_run)

    detect = await plugin.detect(backend)
    assert isinstance(detect, DetectResult)
    assert detect.denylisted is True
    assert detect.version == "0.69.4"
