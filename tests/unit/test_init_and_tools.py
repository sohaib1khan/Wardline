"""Init + tools CLI smoke tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from wardline.cli.init_cmd import run_init
from wardline.cli.tools_cmd import tools_list
from wardline.core.paths import ENV_CONFIG_DIR, ENV_DATA_DIR, describe_storage_layout


def test_describe_storage_layout_contains_vault(tmp_path: Path) -> None:
    text = describe_storage_layout(data_dir=tmp_path / "data", config_dir=tmp_path / "cfg")
    assert "Vault" in text
    assert str(tmp_path / "data" / "vault") in text
    assert "WARDLINE_CONFIG_DIR" in text


def test_run_init_creates_layout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    cfg = tmp_path / "cfg"
    data = tmp_path / "data"
    monkeypatch.setenv(ENV_CONFIG_DIR, str(cfg))
    monkeypatch.setenv(ENV_DATA_DIR, str(data))
    code = run_init()
    assert code == 0
    assert (cfg / "config.toml").is_file()
    assert (data / "vault").is_dir()
    assert (data / "evidence").is_dir()
    out = capsys.readouterr().out
    assert "Storage layout" in out


def test_tools_list_runs(capsys: pytest.CaptureFixture[str]) -> None:
    # Should not raise; prints a table of plugins.
    tools_list(missing_only=False)
    out = capsys.readouterr().out
    assert "Scanner tools" in out or "Plugin" in out
