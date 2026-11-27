"""Unit tests for config/data path helpers and permissions."""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from wardline.core import paths as paths_mod
from wardline.core.paths import (
    DIR_MODE,
    FILE_MODE,
    ensure_data_layout,
    ensure_dir,
    get_config_dir,
    get_data_dir,
    mode_octal,
    write_private_file,
)


def test_get_config_dir_honors_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    target = tmp_path / "cfg"
    monkeypatch.setenv(paths_mod.ENV_CONFIG_DIR, str(target))
    assert get_config_dir() == target.resolve()


def test_get_data_dir_honors_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    target = tmp_path / "data"
    monkeypatch.setenv(paths_mod.ENV_DATA_DIR, str(target))
    assert get_data_dir() == target.resolve()


def test_user_paths_under_xdg(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.delenv(paths_mod.ENV_CONFIG_DIR, raising=False)
    monkeypatch.delenv(paths_mod.ENV_DATA_DIR, raising=False)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg-config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg-data"))
    monkeypatch.setattr(paths_mod, "_is_root", lambda: False)

    assert get_config_dir() == tmp_path / "xdg-config" / "wardline"
    assert get_data_dir() == tmp_path / "xdg-data" / "wardline"


def test_root_paths_use_fhs(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(paths_mod.ENV_CONFIG_DIR, raising=False)
    monkeypatch.delenv(paths_mod.ENV_DATA_DIR, raising=False)
    monkeypatch.setattr(paths_mod, "_is_root", lambda: True)

    assert get_config_dir() == Path("/etc/wardline")
    assert get_data_dir() == Path("/var/lib/wardline")


def test_ensure_data_layout_modes(tmp_path: Path) -> None:
    root = ensure_data_layout(tmp_path / "wardline-data")
    expected = [
        root,
        root / "vault",
        root / "vault" / ".trash",
        root / "evidence",
        root / "cache",
        root / "logs",
    ]
    for path in expected:
        assert path.is_dir()
        assert mode_octal(path) == DIR_MODE


def test_write_private_file_mode(tmp_path: Path) -> None:
    path = tmp_path / "subdir" / "secret.toml"
    write_private_file(path, "token=demo\n")
    assert path.read_text(encoding="utf-8") == "token=demo\n"
    assert mode_octal(path) == FILE_MODE
    assert mode_octal(path.parent) == DIR_MODE


def test_ensure_dir_forces_mode_despite_umask(tmp_path: Path) -> None:
    # Even with a permissive umask, we chmod to 0700 after create.
    old = os.umask(0)
    try:
        path = ensure_dir(tmp_path / "private")
    finally:
        os.umask(old)
    assert stat.S_IMODE(path.stat().st_mode) == DIR_MODE
