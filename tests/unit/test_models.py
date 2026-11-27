"""Unit tests for core Finding/Scan models."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from wardline.core.models import (
    EVIDENCE_MAX_BYTES,
    BackendKind,
    Category,
    Finding,
    FindingStatus,
    HostInfo,
    PluginResult,
    PluginStatus,
    Scan,
    Severity,
    Verdict,
    make_finding_id,
    truncate_evidence,
)


def _finding(**overrides: object) -> Finding:
    base: dict[str, object] = {
        "scan_id": "01ARZ3NDEKTSV4RRFFQ69G5FAV",
        "host": "lab01.example.internal",
        "plugin": "trivy",
        "rule_id": "CVE-2024-6387",
        "category": Category.VULNERABILITY,
        "severity": Severity.HIGH,
        "title": "OpenSSH regreSSHion",
        "location": "openssh@9.6p1",
    }
    base.update(overrides)
    return Finding(**base)  # type: ignore[arg-type]


def test_finding_id_is_stable_hash_of_plugin_rule_location() -> None:
    a = _finding()
    b = _finding(title="different title should not matter")
    expected = make_finding_id("trivy", "CVE-2024-6387", "openssh@9.6p1")
    assert a.id == expected
    assert a.id == b.id


def test_finding_id_changes_when_location_changes() -> None:
    a = _finding(location="pkg@1")
    b = _finding(location="pkg@2")
    assert a.id != b.id


def test_evidence_truncated_to_4kb() -> None:
    big = "A" * (EVIDENCE_MAX_BYTES + 50)
    finding = _finding(evidence=big)
    assert len(finding.evidence.encode("utf-8")) <= EVIDENCE_MAX_BYTES + len("…".encode())
    assert finding.evidence.endswith("…")


def test_truncate_evidence_handles_multibyte_boundary() -> None:
    # 2-byte UTF-8 char near the cut point must not raise.
    text = "é" * (EVIDENCE_MAX_BYTES // 2 + 10)
    out = truncate_evidence(text, max_bytes=10)
    out.encode("utf-8")  # must be valid
    assert out.endswith("…")


def test_finding_defaults() -> None:
    finding = _finding()
    assert finding.verdict == Verdict.NONE
    assert finding.status == FindingStatus.OPEN
    assert finding.cve_ids == []
    assert finding.related == []


def test_scan_round_trip_json() -> None:
    finding = _finding(cve_ids=["CVE-2024-6387"])
    scan = Scan(
        id="01ARZ3NDEKTSV4RRFFQ69G5FAV",
        wardline_version="0.1.0",
        started_at=datetime(2024, 1, 15, 12, 0, tzinfo=UTC),
        finished_at=datetime(2024, 1, 15, 12, 5, tzinfo=UTC),
        profile="quick",
        backend=BackendKind.LOCAL,
        host=HostInfo(
            hostname="lab01.example.internal",
            distro="rocky",
            version="10.1",
            kernel="6.1.0",
            arch="x86_64",
            ram_mb=8192,
            is_root=True,
        ),
        plugin_results=[
            PluginResult(
                plugin="trivy",
                tool_version="0.58.0",
                status=PluginStatus.FINDINGS,
                duration_seconds=12.5,
                exit_code=0,
            )
        ],
        findings=[finding],
        tags=["lab"],
    )
    data = scan.model_dump(mode="json")
    restored = Scan.model_validate(data)
    assert restored.id == scan.id
    assert restored.findings[0].rule_id == "CVE-2024-6387"
    assert restored.host.hostname == "lab01.example.internal"
    assert restored.backend == BackendKind.LOCAL


def test_invalid_severity_rejected() -> None:
    with pytest.raises(ValidationError):
        _finding(severity="super-critical")
