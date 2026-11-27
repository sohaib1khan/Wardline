"""CLI doctor output tests."""

from __future__ import annotations

from rich.console import Console

from wardline.cli.doctor import run_doctor


def test_doctor_prints_tables() -> None:
    console = Console(record=True, width=120)
    code = run_doctor(console=console)
    assert code == 0
    text = console.export_text()
    assert "Wardline" in text
    assert "Host" in text
    assert "Distro" in text
    assert "RAM" in text
    assert "Plugins" in text
    # Dummy is hidden; table should still render cleanly.
    assert "Backend" in text
