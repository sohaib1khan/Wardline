"""Expected listener / ports helpers + CLI normalization."""

from __future__ import annotations

import pytest

from wardline.core.ports import PortError, normalize_listener, parse_listener_list


def test_normalize_listener_defaults_tcp() -> None:
    assert normalize_listener("22") == "22/tcp"
    assert normalize_listener("443/TCP") == "443/tcp"
    assert normalize_listener("53/udp") == "53/udp"


def test_normalize_listener_rejects_bad() -> None:
    with pytest.raises(PortError):
        normalize_listener("0")
    with pytest.raises(PortError):
        normalize_listener("70000")
    with pytest.raises(PortError):
        normalize_listener("http")


def test_parse_listener_list_dedupes() -> None:
    assert parse_listener_list("22, 80/tcp, 22/tcp, 443") == [
        "22/tcp",
        "80/tcp",
        "443/tcp",
    ]
