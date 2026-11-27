"""Theme setting must persist to config.toml and reload."""

from __future__ import annotations

from pathlib import Path

import pytest

from wardline.core.config import load_config, save_config
from wardline.core.paths import ENV_CONFIG_DIR


def test_theme_round_trip(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(ENV_CONFIG_DIR, str(tmp_path))
    cfg = load_config()
    assert cfg.ui.theme == "dark"
    cfg.ui.theme = "light"
    path = save_config(cfg)
    assert path.is_file()
    text = path.read_text(encoding="utf-8")
    assert 'theme = "light"' in text
    reloaded = load_config()
    assert reloaded.ui.theme == "light"
