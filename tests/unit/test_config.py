"""Unit tests for config loading and validation."""

from __future__ import annotations

from pathlib import Path

import pytest

from wardline.core.config import ConfigError, WardlineConfig, default_config, load_config
from wardline.core.models import BackendKind, Severity

EXAMPLE_TOML = """\
[general]
default_profile = "quick"
default_backend = "local"

[ui]
theme = "dark"
reduce_motion = false

[scan.clamav]
paths = ["/home", "/var/www", "/tmp"]
min_ram_mb = 4096

[scan.nmap]
allowed_targets = ["127.0.0.1"]

[scan.ss]
expected_listeners = ["22/tcp", "80/tcp", "443/tcp"]

[scan.false_positives]
chkrootkit = ["/usr/lib/python3/dist-packages/fail2ban/tests/"]

[vault]
auto_save = true
keep_last_n = 0

[evidence]
enabled = false
max_file_mb = 50
max_total_mb = 1024

[alerts]
min_severity = "high"
syslog = true
webhook_env = "WARDLINE_WEBHOOK_URL"
"""


def test_default_config_values() -> None:
    cfg = default_config()
    assert cfg.general.default_profile == "quick"
    assert cfg.general.default_backend == BackendKind.LOCAL
    assert cfg.ui.theme == "dark"
    assert cfg.scan.nmap.allowed_targets == ["127.0.0.1"]
    assert cfg.evidence.enabled is False
    assert cfg.alerts.min_severity == Severity.HIGH


def test_load_missing_returns_defaults(tmp_path: Path) -> None:
    cfg = load_config(tmp_path / "nope.toml", missing_ok=True)
    assert isinstance(cfg, WardlineConfig)
    assert cfg.general.default_profile == "quick"


def test_load_missing_raises_when_required(tmp_path: Path) -> None:
    path = tmp_path / "missing.toml"
    with pytest.raises(ConfigError, match="config file not found") as exc_info:
        load_config(path, missing_ok=False)
    assert path in Path(str(exc_info.value)).parents or str(path) in str(exc_info.value)


def test_load_example_shape(tmp_path: Path) -> None:
    path = tmp_path / "config.toml"
    path.write_text(EXAMPLE_TOML, encoding="utf-8")
    cfg = load_config(path)
    assert cfg.scan.clamav.min_ram_mb == 4096
    assert cfg.scan.ss.expected_listeners == ["22/tcp", "80/tcp", "443/tcp"]
    assert "fail2ban" in cfg.scan.false_positives.chkrootkit[0]
    assert cfg.vault.keep_last_n == 0


def test_load_repo_example_file() -> None:
    repo_example = Path(__file__).resolve().parents[2] / "config.example.toml"
    cfg = load_config(repo_example)
    assert cfg.general.default_backend == BackendKind.LOCAL


def test_nmap_always_includes_localhost(tmp_path: Path) -> None:
    path = tmp_path / "config.toml"
    path.write_text(
        '[scan.nmap]\nallowed_targets = ["192.0.2.10"]\n',
        encoding="utf-8",
    )
    cfg = load_config(path)
    assert cfg.scan.nmap.allowed_targets[0] == "127.0.0.1"
    assert "192.0.2.10" in cfg.scan.nmap.allowed_targets


def test_invalid_toml_is_friendly(tmp_path: Path) -> None:
    path = tmp_path / "bad.toml"
    path.write_text("[[[not valid", encoding="utf-8")
    with pytest.raises(ConfigError, match="TOML parse error") as exc_info:
        load_config(path)
    assert str(path) in str(exc_info.value)


def test_validation_error_is_friendly(tmp_path: Path) -> None:
    path = tmp_path / "bad.toml"
    path.write_text(
        "[vault]\nkeep_last_n = -3\n",
        encoding="utf-8",
    )
    with pytest.raises(ConfigError, match="Invalid configuration") as exc_info:
        load_config(path)
    msg = str(exc_info.value)
    assert "keep_last_n" in msg
    assert str(path) in msg


def test_invalid_theme_is_friendly(tmp_path: Path) -> None:
    path = tmp_path / "bad.toml"
    path.write_text('[ui]\ntheme = "neon"\n', encoding="utf-8")
    with pytest.raises(ConfigError, match="Invalid configuration"):
        load_config(path)


def test_evidence_max_must_be_positive(tmp_path: Path) -> None:
    path = tmp_path / "bad.toml"
    path.write_text("[evidence]\nmax_file_mb = 0\n", encoding="utf-8")
    with pytest.raises(ConfigError, match="positive"):
        load_config(path)
