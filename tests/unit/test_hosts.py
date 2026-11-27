"""Host inventory, sudoers suggestion, known_hosts helpers."""

from __future__ import annotations

from pathlib import Path

import pytest

from wardline.core.hosts import (
    HostInventory,
    HostRecord,
    ensure_known_hosts_file,
    load_hosts,
    save_hosts,
    sudoers_suggestion,
)


def test_save_and_load_hosts(tmp_path: Path) -> None:
    path = tmp_path / "hosts.toml"
    inv = HostInventory(
        fleet_concurrency=3,
        hosts=[
            HostRecord(
                name="lab01",
                host="192.0.2.10",
                user="wardline",
                identity_file="keys/lab01",
                tags=["lab"],
            )
        ],
    )
    save_hosts(inv, path)
    loaded = load_hosts(path)
    assert loaded.fleet_concurrency == 3
    assert loaded.get("lab01").host == "192.0.2.10"
    assert loaded.get("lab01").tags == ["lab"]


def test_get_by_alias(tmp_path: Path) -> None:
    path = tmp_path / "hosts.toml"
    save_hosts(
        HostInventory(
            hosts=[HostRecord(name="a", host="192.0.2.1", alias="lab01.example.internal")]
        ),
        path,
    )
    assert load_hosts(path).get("lab01.example.internal").name == "a"


def test_missing_hosts_ok() -> None:
    inv = load_hosts(Path("/nonexistent/hosts.toml"), missing_ok=True)
    assert inv.hosts == []


def test_sudoers_suggestion_mentions_user_and_nopasswd() -> None:
    text = sudoers_suggestion(user="wardline")
    assert "wardline" in text
    assert "NOPASSWD" in text
    assert "WARDLINE_SCAN" in text
    assert "never edits sudoers" in text.lower() or "Never" in text


def test_ensure_known_hosts(tmp_path: Path) -> None:
    path = tmp_path / "known_hosts"
    created = ensure_known_hosts_file(path)
    assert created.is_file()
    assert created.read_text(encoding="utf-8") == ""


def test_invalid_port() -> None:
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        HostRecord(name="x", host="192.0.2.1", port=0)
