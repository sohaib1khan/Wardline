"""Path safety tests — escape attempts must fail."""

from __future__ import annotations

from pathlib import Path

import pytest

from wardline.core.paths import ensure_dir, write_private_file
from wardline.vault.safety import (
    VaultSafetyError,
    assert_inside_vault,
    empty_trash,
    soft_delete_report,
)


def test_assert_inside_vault_accepts_child(tmp_path: Path) -> None:
    vault = ensure_dir(tmp_path / "vault")
    child = ensure_dir(vault / "host" / "scan1")
    assert assert_inside_vault(child, vault) == child.resolve()


def test_assert_inside_vault_rejects_dotdot(tmp_path: Path) -> None:
    vault = ensure_dir(tmp_path / "vault")
    escape = vault / ".." / "outside"
    with pytest.raises(VaultSafetyError, match="outside Vault"):
        assert_inside_vault(escape, vault)


def test_assert_inside_vault_rejects_absolute_outside(tmp_path: Path) -> None:
    vault = ensure_dir(tmp_path / "vault")
    with pytest.raises(VaultSafetyError, match="outside Vault"):
        assert_inside_vault(Path("/etc/passwd"), vault)


def test_assert_inside_vault_rejects_symlink_escape(tmp_path: Path) -> None:
    vault = ensure_dir(tmp_path / "vault")
    outside = ensure_dir(tmp_path / "outside")
    link = vault / "sneaky"
    link.symlink_to(outside)
    with pytest.raises(VaultSafetyError):
        assert_inside_vault(link / "file.txt", vault)


def test_soft_delete_moves_to_trash(tmp_path: Path) -> None:
    vault = ensure_dir(tmp_path / "vault")
    report = ensure_dir(vault / "host" / "scanA")
    write_private_file(report / "scan.json", "{}\n")
    dest = soft_delete_report(report, vault)
    assert not report.exists()
    assert dest.exists()
    assert dest.parent.name == ".trash"
    assert (dest / "scan.json").is_file()


def test_soft_delete_refuses_vault_root(tmp_path: Path) -> None:
    vault = ensure_dir(tmp_path / "vault")
    with pytest.raises(VaultSafetyError, match="Vault root"):
        soft_delete_report(vault, vault)


def test_empty_trash_requires_confirm(tmp_path: Path) -> None:
    vault = ensure_dir(tmp_path / "vault")
    with pytest.raises(VaultSafetyError, match="confirm"):
        empty_trash(vault, confirm=False)


def test_empty_trash_removes_contents(tmp_path: Path) -> None:
    vault = ensure_dir(tmp_path / "vault")
    report = ensure_dir(vault / "host" / "scanB")
    write_private_file(report / "scan.json", "{}\n")
    soft_delete_report(report, vault)
    removed = empty_trash(vault, confirm=True)
    assert removed >= 1
    assert list((vault / ".trash").iterdir()) == []
