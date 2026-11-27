"""Unit tests for os-release parsing and distro classification."""

from __future__ import annotations

from pathlib import Path

import pytest

from wardline.core.distro import PackageManager, detect_distro, parse_os_release

ROCKY = """\
NAME="Rocky Linux"
VERSION="10.1 (Red Quartz)"
ID="rocky"
ID_LIKE="rhel centos fedora"
VERSION_ID="10.1"
PLATFORM_ID="platform:el10"
PRETTY_NAME="Rocky Linux 10.1 (Red Quartz)"
ANSI_COLOR="0;32"
LOGO="fedora-logo-icon"
CPE_NAME="cpe:/o:rocky:rocky:10.1"
HOME_URL="https://rockylinux.org/"
"""

UBUNTU = """\
PRETTY_NAME="Ubuntu 24.04.1 LTS"
NAME="Ubuntu"
VERSION_ID="24.04"
VERSION="24.04.1 LTS (Noble Numbat)"
VERSION_CODENAME=noble
ID=ubuntu
ID_LIKE=debian
HOME_URL="https://www.ubuntu.com/"
"""

DEBIAN = """\
PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"
NAME="Debian GNU/Linux"
VERSION_ID="12"
VERSION="12 (bookworm)"
VERSION_CODENAME=bookworm
ID=debian
HOME_URL="https://www.debian.org/"
"""


def test_parse_os_release_strips_quotes() -> None:
    fields = parse_os_release(ROCKY)
    assert fields["ID"] == "rocky"
    assert fields["VERSION_ID"] == "10.1"
    assert fields["PRETTY_NAME"] == "Rocky Linux 10.1 (Red Quartz)"


def test_detect_rocky(tmp_path: Path) -> None:
    path = tmp_path / "os-release"
    path.write_text(ROCKY, encoding="utf-8")
    info = detect_distro(path)
    assert info.id == "rocky"
    assert info.family == "rhel"
    assert info.is_rhel_family
    assert info.package_manager == PackageManager.DNF
    assert info.version_id == "10.1"


def test_detect_ubuntu(tmp_path: Path) -> None:
    path = tmp_path / "os-release"
    path.write_text(UBUNTU, encoding="utf-8")
    info = detect_distro(path)
    assert info.id == "ubuntu"
    assert info.family == "debian"
    assert info.is_debian_family
    assert info.package_manager == PackageManager.APT
    assert info.version_codename == "noble"


def test_detect_debian(tmp_path: Path) -> None:
    path = tmp_path / "os-release"
    path.write_text(DEBIAN, encoding="utf-8")
    info = detect_distro(path)
    assert info.id == "debian"
    assert info.package_manager == PackageManager.APT


def test_missing_os_release_friendly(tmp_path: Path) -> None:
    missing = tmp_path / "nope"
    with pytest.raises(FileNotFoundError, match="Cannot detect distro"):
        detect_distro(missing)


def test_detect_live_host_os_release() -> None:
    # Smoke: real file on this lab host should parse without error.
    info = detect_distro()
    assert info.id
    assert info.pretty_name
