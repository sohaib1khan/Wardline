"""Parser tests for Phase 6 plugins (sanitized fixtures)."""

from __future__ import annotations

import json
from pathlib import Path

from wardline.backends.local import LocalBackend
from wardline.core.models import PluginStatus, Severity
from wardline.core.profiles import PROFILES, resolve_plugin_names
from wardline.plugins.aide import AidePlugin
from wardline.plugins.base import get_registry
from wardline.plugins.chkrootkit import ChkrootkitPlugin
from wardline.plugins.clamav import ClamAVPlugin
from wardline.plugins.nmap import NmapPlugin
from wardline.plugins.openscap import OpenScapPlugin
from wardline.plugins.patch_status import PatchStatusPlugin
from wardline.plugins.persistence import PersistencePlugin
from wardline.plugins.pkg_verify import PkgVerifyPlugin
from wardline.plugins.rkhunter import RkhunterPlugin

FIX = Path(__file__).resolve().parents[1] / "fixtures"
SCAN = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
HOST = "lab01.example.internal"


def test_registry_has_phase6_plugins() -> None:
    registry = get_registry(refresh=True)
    for name in (
        "clamav",
        "rkhunter",
        "chkrootkit",
        "aide",
        "nmap",
        "openscap",
        "pkg_verify",
        "patch_status",
        "persistence",
    ):
        assert name in registry


def test_profiles_include_phase6() -> None:
    assert "patch_status" in PROFILES["quick"].plugins
    assert "clamav" in PROFILES["deep"].plugins
    assert "nmap" in resolve_plugin_names(profile="deep")


def test_clamav_parser() -> None:
    raw = (FIX / "clamav" / "infected.txt").read_text(encoding="utf-8")
    result = ClamAVPlugin().parse(raw, 1, scan_id=SCAN, host=HOST)
    assert any(f.severity == Severity.CRITICAL for f in result.findings)
    assert any("EICAR" in f.title or "EICAR" in f.rule_id for f in result.findings)


def test_rkhunter_parser() -> None:
    raw = (FIX / "rkhunter" / "warnings.txt").read_text(encoding="utf-8")
    result = RkhunterPlugin().parse(raw, 1, scan_id=SCAN, host=HOST)
    assert any(f.rule_id == "RKH-WEB-CMD" for f in result.findings)
    changed = next(f for f in result.findings if f.rule_id == "RKH-FILE-CHANGED")
    assert changed.location == "/usr/bin/sudo"
    # Noisy SSH option → low
    ssh = next(f for f in result.findings if "PermitRootLogin" in f.title)
    assert ssh.severity == Severity.LOW


def test_chkrootkit_false_positives() -> None:
    raw = (FIX / "chkrootkit" / "sample.txt").read_text(encoding="utf-8")
    result = ChkrootkitPlugin().parse(
        raw,
        0,
        scan_id=SCAN,
        host=HOST,
        options={"false_positives": ["/usr/lib/python3/dist-packages/fail2ban/tests/"]},
    )
    assert any(
        f.rule_id == "CHK-INFECTED" and f.severity == Severity.CRITICAL for f in result.findings
    )
    # fail2ban path suppressed
    assert not any("fail2ban" in f.location for f in result.findings)
    assert any(f.rule_id == "CHK-HIDDEN" for f in result.findings)


def test_aide_parser_severities() -> None:
    raw = (FIX / "aide" / "check.txt").read_text(encoding="utf-8")
    result = AidePlugin().parse(raw, 1, scan_id=SCAN, host=HOST)
    by_loc = {f.location: f for f in result.findings}
    assert by_loc["/usr/bin/.evil"].severity == Severity.CRITICAL
    assert by_loc["/usr/bin/sudo"].severity == Severity.HIGH
    assert by_loc["/etc/passwd"].severity == Severity.HIGH


def test_nmap_xml_and_scope_refusal() -> None:
    raw = (FIX / "nmap" / "localhost.xml").read_text(encoding="utf-8")
    plugin = NmapPlugin()
    result = plugin.parse(
        raw,
        0,
        scan_id=SCAN,
        host=HOST,
        options={"refused_targets": ["198.51.100.50"]},
    )
    assert any(f.rule_id == "NMAP-SCOPE" for f in result.findings)
    assert any(f.rule_id == "CVE-2024-6387" for f in result.findings)
    assert any(f.rule_id.startswith("NMAP-PORT-22") for f in result.findings)

    opts: dict = {
        "allowed_targets": ["127.0.0.1"],
        "targets": ["127.0.0.1", "198.51.100.50"],
    }
    cmds = plugin.build_commands(LocalBackend(apply_priority=False), opts)
    assert len(cmds) == 1
    assert opts["refused_targets"] == ["198.51.100.50"]


def test_openscap_failed_rules() -> None:
    raw = (FIX / "openscap" / "results.xml").read_text(encoding="utf-8")
    result = OpenScapPlugin().parse(raw, 2, scan_id=SCAN, host=HOST)
    assert len(result.findings) == 2
    assert any(f.severity == Severity.HIGH for f in result.findings)
    assert OpenScapPlugin().interpret_exit_code(2) == PluginStatus.OK


def test_pkg_verify_debsums_and_rpm() -> None:
    deb = (FIX / "pkg_verify" / "debsums.txt").read_text(encoding="utf-8")
    rpm = (FIX / "pkg_verify" / "rpm_va.txt").read_text(encoding="utf-8")
    plugin = PkgVerifyPlugin()
    deb_r = plugin.parse(deb, 2, scan_id=SCAN, host=HOST)
    assert any(
        f.location == "/usr/bin/sudo" and f.severity.value == "critical" for f in deb_r.findings
    )
    rpm_r = plugin.parse(rpm, 1, scan_id=SCAN, host=HOST)
    sudo = next(f for f in rpm_r.findings if f.location == "/usr/bin/sudo")
    assert sudo.severity == Severity.CRITICAL
    hosts = next(f for f in rpm_r.findings if f.location == "/etc/hosts")
    assert hosts.severity in {Severity.HIGH, Severity.MEDIUM}


def test_patch_status_parser() -> None:
    raw = (
        (FIX / "patch_status" / "needrestart.txt").read_text(encoding="utf-8")
        + "\n"
        + (FIX / "patch_status" / "dnf_updateinfo.txt").read_text(encoding="utf-8")
        + "\nREBOOT_REQUIRED:0\n"
    )
    result = PatchStatusPlugin().parse(raw, 0, scan_id=SCAN, host=HOST)
    assert any(f.rule_id == "PATCH-REBOOT" for f in result.findings)
    assert any("ssh.service" in f.location for f in result.findings)
    assert any(f.rule_id.startswith("PATCH-DNF-") for f in result.findings)


def test_persistence_diff() -> None:
    a = json.loads((FIX / "persistence" / "snapshot_a.json").read_text(encoding="utf-8"))
    b = json.loads((FIX / "persistence" / "snapshot_b.json").read_text(encoding="utf-8"))
    raw = json.dumps(b)
    result = PersistencePlugin().parse(
        raw,
        0,
        scan_id=SCAN,
        host=HOST,
        options={"previous_persistence": a},
    )
    assert any("evil" in f.title for f in result.findings)
    assert any(
        f.severity == Severity.HIGH and "authorized_keys" in f.title for f in result.findings
    )
    assert any("toor" in f.title or "UID 0" in f.title for f in result.findings)
    assert any("svc-backdoor" in f.title for f in result.findings)
