"""Correlation rules R1-R7."""

from __future__ import annotations

from wardline.core.models import (
    Category,
    Finding,
    PluginResult,
    PluginStatus,
    Severity,
    Verdict,
)
from wardline.correlate import apply_correlation
from wardline.correlate.rules.r1_backport import R1BackportCheck
from wardline.correlate.rules.r2_changed_binary import R2ChangedBinary


def _f(
    *,
    plugin: str,
    rule_id: str,
    category: Category,
    severity: Severity = Severity.MEDIUM,
    location: str = "",
    cve_ids: list[str] | None = None,
    title: str = "t",
    evidence: str = "",
    fix_hint: str = "",
    scan_id: str = "scan1",
    host: str = "host1",
) -> Finding:
    return Finding(
        scan_id=scan_id,
        host=host,
        plugin=plugin,
        rule_id=rule_id,
        category=category,
        severity=severity,
        title=title,
        location=location or rule_id,
        evidence=evidence,
        cve_ids=cve_ids or [],
        fix_hint=fix_hint,
    )


def test_r1_nmap_backport_likely_false_positive() -> None:
    """Nmap CVE absent from Trivy → likely_false_positive (acceptance case)."""
    nmap = _f(
        plugin="nmap",
        rule_id="CVE-2024-6387",
        category=Category.VULNERABILITY,
        severity=Severity.HIGH,
        location="127.0.0.1:22/tcp",
        cve_ids=["CVE-2024-6387"],
        title="OpenSSH banner CVE-2024-6387",
    )
    # Trivy ran and reported a *different* CVE — proves scan data exists.
    trivy = _f(
        plugin="trivy",
        rule_id="CVE-2025-32463",
        category=Category.VULNERABILITY,
        severity=Severity.CRITICAL,
        location="sudo@1.9.13",
        cve_ids=["CVE-2025-32463"],
        title="sudo CVE",
        fix_hint="Upgrade sudo to 1.9.13p3-3+deb12u1",
    )
    outcome = R1BackportCheck().apply([nmap, trivy], scan_id="s", host="h")
    assert nmap.verdict == Verdict.LIKELY_FALSE_POSITIVE
    assert "backported" in nmap.verdict_reason.lower()
    assert outcome.changed


def test_r1_nmap_confirmed_when_trivy_shares_cve() -> None:
    nmap = _f(
        plugin="nmap",
        rule_id="CVE-2025-32463",
        category=Category.VULNERABILITY,
        severity=Severity.CRITICAL,
        cve_ids=["CVE-2025-32463"],
    )
    trivy = _f(
        plugin="trivy",
        rule_id="CVE-2025-32463",
        category=Category.VULNERABILITY,
        severity=Severity.CRITICAL,
        cve_ids=["CVE-2025-32463"],
        fix_hint="Upgrade sudo to 1.9.13p3-3+deb12u1",
    )
    R1BackportCheck().apply([nmap, trivy], scan_id="s", host="h")
    assert nmap.verdict == Verdict.CONFIRMED
    assert trivy.id in nmap.related


def test_r1_needs_review_without_trivy() -> None:
    nmap = _f(
        plugin="nmap",
        rule_id="CVE-2024-6387",
        category=Category.VULNERABILITY,
        cve_ids=["CVE-2024-6387"],
    )
    R1BackportCheck().apply([nmap], scan_id="s", host="h")
    assert nmap.verdict == Verdict.NEEDS_REVIEW


def test_r2_dirty_pkg_verify_locks_baseline() -> None:
    aide = _f(
        plugin="aide",
        rule_id="AIDE-CHANGED-/usr/bin/sudo",
        category=Category.INTEGRITY,
        severity=Severity.HIGH,
        location="/usr/bin/sudo",
        title="AIDE changed: /usr/bin/sudo",
    )
    dirty = _f(
        plugin="pkg_verify",
        rule_id="DEBSUMS-/usr/bin/sudo",
        category=Category.INTEGRITY,
        severity=Severity.CRITICAL,
        location="/usr/bin/sudo",
        title="debsums mismatch",
    )
    outcome = R2ChangedBinary().apply(
        [aide, dirty],
        scan_id="s",
        host="h",
        plugin_results=[
            PluginResult(plugin="pkg_verify", status=PluginStatus.FINDINGS),
        ],
    )
    assert outcome.baseline_locked
    assert any(f.rule_id.startswith("CORR-R2-TAMPER") for f in outcome.findings)
    tamper = next(f for f in outcome.findings if f.rule_id.startswith("CORR-R2-TAMPER"))
    assert tamper.severity == Severity.CRITICAL
    assert aide.verdict == Verdict.CONFIRMED


def test_r2_clean_pkg_verify_needs_review() -> None:
    aide = _f(
        plugin="aide",
        rule_id="AIDE-CHANGED-/usr/bin/sudo",
        category=Category.INTEGRITY,
        severity=Severity.HIGH,
        location="/usr/bin/sudo",
    )
    outcome = R2ChangedBinary().apply(
        [aide],
        scan_id="s",
        host="h",
        plugin_results=[PluginResult(plugin="pkg_verify", status=PluginStatus.OK)],
    )
    assert not outcome.baseline_locked
    assert aide.verdict == Verdict.NEEDS_REVIEW
    assert "package db" in aide.verdict_reason.lower() or "update" in aide.verdict_reason.lower()


def test_r3_lynis_linked_to_trivy() -> None:
    lynis = _f(
        plugin="lynis",
        rule_id="PKGS-7392",
        category=Category.HARDENING,
        location="PKGS-7392",
    )
    trivy = _f(
        plugin="trivy",
        rule_id="CVE-2025-32463",
        category=Category.VULNERABILITY,
        cve_ids=["CVE-2025-32463"],
    )
    result = apply_correlation([lynis, trivy], scan_id="s", host="h")
    assert lynis.verdict == Verdict.NEEDS_REVIEW
    assert "covered" in lynis.verdict_reason.lower()
    assert trivy.id in lynis.related
    assert "R3" in result.rules_fired


def test_r4_merges_ss_and_nmap_port() -> None:
    ss = _f(
        plugin="ss_baseline",
        rule_id="SS-LISTEN-22-tcp",
        category=Category.NETWORK,
        location="0.0.0.0:22 (22/tcp)",
        evidence="tcp LISTEN 0.0.0.0:22",
    )
    nmap = _f(
        plugin="nmap",
        rule_id="NMAP-PORT-22-tcp",
        category=Category.NETWORK,
        severity=Severity.INFO,
        location="127.0.0.1:22/tcp",
        evidence="open tcp/22 ssh",
    )
    apply_correlation([ss, nmap], scan_id="s", host="h")
    assert ss.verdict == Verdict.CONFIRMED
    assert "[nmap]" in ss.evidence
    assert nmap.id in ss.related
    assert nmap.verdict == Verdict.NEEDS_REVIEW


def test_r5_patched_not_active() -> None:
    trivy = _f(
        plugin="trivy",
        rule_id="CVE-2025-32463",
        category=Category.VULNERABILITY,
        cve_ids=["CVE-2025-32463"],
        fix_hint="Upgrade sudo to 1.9.13p3-3+deb12u1",
        location="sudo@1.9.13",
    )
    reboot = _f(
        plugin="patch_status",
        rule_id="PATCH-REBOOT",
        category=Category.PATCHING,
        severity=Severity.HIGH,
        location="reboot",
    )
    result = apply_correlation([trivy, reboot], scan_id="s", host="h")
    r5 = [f for f in result.findings if f.rule_id.startswith("CORR-R5-")]
    assert len(r5) == 1
    assert r5[0].category == Category.PATCHING
    assert "not running" in r5[0].title.lower() or "not running" in r5[0].description.lower()


def test_r6_account_tampering() -> None:
    aide = _f(
        plugin="aide",
        rule_id="AIDE-CHANGED-/etc/passwd",
        category=Category.INTEGRITY,
        severity=Severity.HIGH,
        location="/etc/passwd",
    )
    user = _f(
        plugin="persistence",
        rule_id="PERS-USER-evil",
        category=Category.PERSISTENCE,
        severity=Severity.MEDIUM,
        location="evil",
    )
    result = apply_correlation([aide, user], scan_id="s", host="h")
    assert any(f.rule_id == "CORR-R6-ACCOUNT" for f in result.findings)
    assert any(f.severity == Severity.CRITICAL and "account" in f.title.lower() for f in result.findings)


def test_r7_malware_and_persistence() -> None:
    clam = _f(
        plugin="clamav",
        rule_id="CLAMAV-Eicar",
        category=Category.MALWARE,
        severity=Severity.CRITICAL,
        location="/tmp/eicar",
        title="Eicar-Test-Signature FOUND",
    )
    cron = _f(
        plugin="persistence",
        rule_id="PERS-CRON-/etc/cron.d/evil",
        category=Category.PERSISTENCE,
        location="/etc/cron.d/evil",
    )
    result = apply_correlation([clam, cron], scan_id="s", host="h")
    assert any(f.rule_id == "CORR-R7-INCIDENT" for f in result.findings)
    assert result.findings[-1].severity == Severity.CRITICAL
