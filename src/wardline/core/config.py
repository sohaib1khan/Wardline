"""Load and validate Wardline TOML configuration."""

from __future__ import annotations

import contextlib
import tomllib
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field, ValidationError, field_validator

from wardline.core.models import BackendKind, Severity
from wardline.core.paths import config_file_path, ensure_dir, get_config_dir


class ConfigError(Exception):
    """User-facing configuration error with a friendly message."""

    def __init__(self, message: str, *, path: Path | None = None) -> None:
        self.path = path
        prefix = f"{path}: " if path is not None else ""
        super().__init__(f"{prefix}{message}")


class GeneralConfig(BaseModel):
    default_profile: str = "quick"
    default_backend: BackendKind = BackendKind.LOCAL


class UiConfig(BaseModel):
    theme: Literal["dark", "light"] = "dark"
    reduce_motion: bool = False


class ClamavConfig(BaseModel):
    paths: list[str] = Field(default_factory=lambda: ["/home", "/var/www", "/tmp"])
    min_ram_mb: int = 4096


class NmapConfig(BaseModel):
    allowed_targets: list[str] = Field(default_factory=lambda: ["127.0.0.1"])

    @field_validator("allowed_targets")
    @classmethod
    def _ensure_localhost(cls, value: list[str]) -> list[str]:
        # Safety rule 6: always allow loopback; keep user entries too.
        normalized = list(dict.fromkeys(value))  # preserve order, dedupe
        if "127.0.0.1" not in normalized:
            normalized.insert(0, "127.0.0.1")
        return normalized


class SsConfig(BaseModel):
    expected_listeners: list[str] = Field(default_factory=lambda: ["22/tcp", "80/tcp", "443/tcp"])


class FalsePositivesConfig(BaseModel):
    chkrootkit: list[str] = Field(default_factory=list)


class ScanConfig(BaseModel):
    clamav: ClamavConfig = Field(default_factory=ClamavConfig)
    nmap: NmapConfig = Field(default_factory=NmapConfig)
    ss: SsConfig = Field(default_factory=SsConfig)
    false_positives: FalsePositivesConfig = Field(default_factory=FalsePositivesConfig)


class VaultConfig(BaseModel):
    auto_save: bool = True
    keep_last_n: int = 0

    @field_validator("keep_last_n")
    @classmethod
    def _non_negative(cls, value: int) -> int:
        if value < 0:
            raise ValueError("keep_last_n must be >= 0 (0 means keep all)")
        return value


class EvidenceConfig(BaseModel):
    enabled: bool = False
    max_file_mb: int = 50
    max_total_mb: int = 1024

    @field_validator("max_file_mb", "max_total_mb")
    @classmethod
    def _positive(cls, value: int) -> int:
        if value <= 0:
            raise ValueError("must be a positive integer")
        return value


class AlertsConfig(BaseModel):
    min_severity: Severity = Severity.HIGH
    syslog: bool = True
    webhook_env: str = "WARDLINE_WEBHOOK_URL"


class WardlineConfig(BaseModel):
    general: GeneralConfig = Field(default_factory=GeneralConfig)
    ui: UiConfig = Field(default_factory=UiConfig)
    scan: ScanConfig = Field(default_factory=ScanConfig)
    vault: VaultConfig = Field(default_factory=VaultConfig)
    evidence: EvidenceConfig = Field(default_factory=EvidenceConfig)
    alerts: AlertsConfig = Field(default_factory=AlertsConfig)


def _friendly_validation_error(exc: ValidationError) -> str:
    parts: list[str] = []
    for err in exc.errors():
        loc = ".".join(str(x) for x in err.get("loc", ()))
        msg = err.get("msg", "invalid value")
        if loc:
            parts.append(f"{loc}: {msg}")
        else:
            parts.append(msg)
    return "Invalid configuration — " + "; ".join(parts)


def load_config(
    path: Path | None = None,
    *,
    missing_ok: bool = True,
) -> WardlineConfig:
    """Load config from TOML. Missing file returns defaults when missing_ok."""
    cfg_path = path if path is not None else config_file_path()

    if not cfg_path.exists():
        if missing_ok:
            return WardlineConfig()
        raise ConfigError(
            "config file not found. Copy config.example.toml to this path and edit it.",
            path=cfg_path,
        )

    try:
        text = cfg_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"cannot read config file: {exc}", path=cfg_path) from exc

    try:
        raw = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"TOML parse error: {exc}", path=cfg_path) from exc

    if not isinstance(raw, dict):
        raise ConfigError("config root must be a table", path=cfg_path)

    try:
        return WardlineConfig.model_validate(raw)
    except ValidationError as exc:
        raise ConfigError(_friendly_validation_error(exc), path=cfg_path) from exc


def default_config() -> WardlineConfig:
    return WardlineConfig()


def ensure_config_dir() -> Path:
    return ensure_dir(get_config_dir())


def save_config(config: WardlineConfig, path: Path | None = None) -> Path:
    """Write config as TOML atomically (temp file + replace), mode 0600."""
    cfg_path = path if path is not None else config_file_path()
    ensure_dir(cfg_path.parent)
    text = _config_to_toml(config)
    tmp_path = cfg_path.with_suffix(cfg_path.suffix + ".tmp")
    try:
        tmp_path.write_text(text, encoding="utf-8")
        tmp_path.chmod(0o600)
        tmp_path.replace(cfg_path)
    except OSError:
        # Best-effort cleanup of the temp file, then re-raise.
        try:
            if tmp_path.exists():
                tmp_path.unlink()
        except OSError:
            pass
        raise
    with contextlib.suppress(OSError):
        cfg_path.chmod(0o600)
    return cfg_path


def ensure_user_config(*, force_defaults: bool = False) -> Path:
    """Create config.toml with defaults if missing (or overwrite when forced)."""
    ensure_config_dir()
    cfg_path = config_file_path()
    if cfg_path.exists() and not force_defaults:
        return cfg_path
    return save_config(default_config(), cfg_path)


def _config_to_toml(config: WardlineConfig) -> str:
    """Serialize WardlineConfig to TOML without adding a new dependency."""
    lines: list[str] = [
        "[general]",
        f'default_profile = "{config.general.default_profile}"',
        f'default_backend = "{config.general.default_backend.value}"',
        "",
        "[ui]",
        f'theme = "{config.ui.theme}"',
        f"reduce_motion = {'true' if config.ui.reduce_motion else 'false'}",
        "",
        "[scan.clamav]",
        f"paths = {_toml_str_list(config.scan.clamav.paths)}",
        f"min_ram_mb = {config.scan.clamav.min_ram_mb}",
        "",
        "[scan.nmap]",
        f"allowed_targets = {_toml_str_list(config.scan.nmap.allowed_targets)}",
        "",
        "[scan.ss]",
        f"expected_listeners = {_toml_str_list(config.scan.ss.expected_listeners)}",
        "",
        "[scan.false_positives]",
        f"chkrootkit = {_toml_str_list(config.scan.false_positives.chkrootkit)}",
        "",
        "[vault]",
        f"auto_save = {'true' if config.vault.auto_save else 'false'}",
        f"keep_last_n = {config.vault.keep_last_n}",
        "",
        "[evidence]",
        f"enabled = {'true' if config.evidence.enabled else 'false'}",
        f"max_file_mb = {config.evidence.max_file_mb}",
        f"max_total_mb = {config.evidence.max_total_mb}",
        "",
        "[alerts]",
        f'min_severity = "{config.alerts.min_severity.value}"',
        f"syslog = {'true' if config.alerts.syslog else 'false'}",
        f'webhook_env = "{config.alerts.webhook_env}"',
        "",
    ]
    return "\n".join(lines)


def _toml_str_list(values: list[str]) -> str:
    escaped = [v.replace("\\", "\\\\").replace('"', '\\"') for v in values]
    inner = ", ".join(f'"{v}"' for v in escaped)
    return f"[{inner}]"
