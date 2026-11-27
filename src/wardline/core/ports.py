"""Expected listener (port/proto) helpers for ss_baseline config."""

from __future__ import annotations

import re

_PORT_RE = re.compile(r"^(\d{1,5})(?:/(tcp|udp))?$", re.IGNORECASE)


class PortError(ValueError):
    """Invalid port/proto specification."""


def normalize_listener(raw: str, *, default_proto: str = "tcp") -> str:
    """Normalize ``22``, ``22/tcp``, ``443/UDP`` → ``22/tcp`` style."""
    text = raw.strip().lower()
    if not text:
        raise PortError("empty port")
    match = _PORT_RE.fullmatch(text)
    if not match:
        raise PortError(f"invalid port spec {raw!r}; use PORT or PORT/tcp|udp")
    port = int(match.group(1))
    if port < 1 or port > 65535:
        raise PortError(f"port out of range: {port}")
    proto = (match.group(2) or default_proto).lower()
    if proto not in {"tcp", "udp"}:
        raise PortError(f"unsupported proto {proto!r}")
    return f"{port}/{proto}"


def parse_listener_list(raw: str) -> list[str]:
    """Split a comma/whitespace list into normalized listeners (deduped, order kept)."""
    parts = [p for chunk in raw.replace(";", ",").split(",") for p in chunk.split()]
    out: list[str] = []
    seen: set[str] = set()
    for part in parts:
        norm = normalize_listener(part)
        if norm not in seen:
            seen.add(norm)
            out.append(norm)
    return out
