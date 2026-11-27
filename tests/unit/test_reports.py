"""Report rendering and redaction tests."""

from __future__ import annotations

from datetime import UTC, datetime

from wardline.core.models import (
    BackendKind,
    Category,
    Finding,
    HostInfo,
    Scan,
    Severity,
)
from wardline.core.scoring import build_scores, build_summary
from wardline.reports.html import render_html
from wardline.reports.markdown import render_markdown
from wardline.reports.redact import redact_scan, redact_text
from wardline.vault.diff import DiffKind, diff_scans


def _scan(scan_id: str = "01ARZ3NDEKTSV4RRFFQ69G5FAV") -> Scan:
    findings = [
        Finding(
            scan_id=scan_id,
            host="lab01.example.internal",
            plugin="trivy",
            rule_id="CVE-2024-6387",
            category=Category.VULNERABILITY,
            severity=Severity.HIGH,
            title="OpenSSH issue",
            location="openssh@1:9.2",
            evidence="Found on 192.0.2.10 path /home/alice/app",
            cve_ids=["CVE-2024-6387"],
        )
    ]
    return Scan(
        id=scan_id,
        wardline_version="0.1.0",
        started_at=datetime(2024, 6, 1, 12, 0, tzinfo=UTC),
        finished_at=datetime(2024, 6, 1, 12, 1, tzinfo=UTC),
        profile="quick",
        backend=BackendKind.LOCAL,
        host=HostInfo(hostname="lab01.example.internal", distro="debian"),
        findings=findings,
        summary=build_summary(findings),
        scores=build_scores(findings),
    )


def test_markdown_and_html_contain_core_fields() -> None:
    scan = _scan()
    md = render_markdown(scan)
    assert "Posture score" in md
    assert "CVE-2024-6387" in md
    html = render_html(scan)
    assert "WARDLINE" in html
    assert "Posture" in html
    assert "CVE-2024-6387" in html
    assert "cdn." not in html.lower()


def test_redact_masks_ip_home_host() -> None:
    text = redact_text(
        "user alice@lab01.example.internal at 192.0.2.10 /home/alice/x",
        hostname="lab01.example.internal",
    )
    assert "192.0.2.10" not in text
    assert "/home/alice" not in text
    assert "lab01.example.internal" not in text
    assert "REDACTED-HOST" in text or "user@" in text

    redacted = redact_scan(_scan())
    assert redacted.host.hostname == "REDACTED-HOST"
    assert "192.0.2.10" not in redacted.findings[0].evidence


def test_diff_new_resolved_changed() -> None:
    a = _scan("01AAAAAAAAAAAAAAAAAAAAAAAA")
    b = _scan("01BBBBBBBBBBBBBBBBBBBBBBBB")
    # Change severity on the shared finding id (same plugin/rule/location).
    b.findings[0].severity = Severity.CRITICAL
    # Add a new finding.
    b.findings.append(
        Finding(
            scan_id=b.id,
            host=b.host.hostname,
            plugin="ss_baseline",
            rule_id="SS-LISTEN-1-tcp",
            category=Category.NETWORK,
            severity=Severity.MEDIUM,
            title="new listener",
            location="127.0.0.1:1",
        )
    )
    # Drop original from a copy for resolved: build a without findings for resolved case
    a_only = _scan("01CCCCCCCCCCCCCCCCCCCCCCCC")
    a_only.findings = [
        Finding(
            scan_id=a_only.id,
            host=a_only.host.hostname,
            plugin="lynis",
            rule_id="SSH-7408",
            category=Category.HARDENING,
            severity=Severity.MEDIUM,
            title="old finding",
            location="SSH-7408",
        )
    ]
    a_only.summary = build_summary(a_only.findings)
    a_only.scores = build_scores(a_only.findings)

    # Diff a (with trivy finding) vs b (changed + new)
    result = diff_scans(a, b)
    kinds = {i.kind for i in result.items}
    assert DiffKind.CHANGED in kinds
    assert DiffKind.NEW in kinds

    result2 = diff_scans(a_only, a)
    assert any(i.kind == DiffKind.RESOLVED for i in result2.items) or any(
        i.kind == DiffKind.NEW for i in diff_scans(a_only, a).items
    )
    # a_only has lynis finding not in a → resolved when going a_only → a
    resolved = diff_scans(a_only, a)
    assert resolved.resolved_count == 1
    assert resolved.new_count == 1
