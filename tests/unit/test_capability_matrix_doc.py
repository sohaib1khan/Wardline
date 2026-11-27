"""docs/capability-matrix.md stays in sync with plugin metadata."""

from __future__ import annotations

from pathlib import Path

from wardline.core.capability_matrix import render_capability_matrix
from wardline.plugins.base import get_registry

REPO = Path(__file__).resolve().parents[2]
DOC = REPO / "docs" / "capability-matrix.md"


def test_checked_in_matrix_matches_generator() -> None:
    expected = render_capability_matrix(get_registry()).rstrip() + "\n"
    assert DOC.is_file(), "run: uv run wardline docker matrix"
    assert DOC.read_text(encoding="utf-8") == expected
