"""Parser tests for ss_baseline."""

from __future__ import annotations

from pathlib import Path

from wardline.core.models import Severity
from wardline.plugins.ss_baseline import SsBaselinePlugin

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "ss" / "sample_listeners.txt"
SCAN_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
HOST = "lab01.example.internal"


def test_ss_parser_flags_unexplained_and_exposed_db() -> None:
    raw = FIXTURE.read_text(encoding="utf-8")
    plugin = SsBaselinePlugin()
    result = plugin.parse(
        raw,
        0,
        scan_id=SCAN_ID,
        host=HOST,
        options={"expected_listeners": ["22/tcp", "80/tcp", "443/tcp"]},
    )

    by_rule = {f.rule_id: f for f in result.findings}
    assert "SS-LISTEN-3306-tcp" in by_rule
    assert by_rule["SS-LISTEN-3306-tcp"].severity == Severity.HIGH
    assert "SS-LISTEN-6379-tcp" in by_rule
    assert by_rule["SS-LISTEN-6379-tcp"].severity == Severity.HIGH
    assert "SS-LISTEN-5432-tcp" in by_rule
    assert by_rule["SS-LISTEN-5432-tcp"].severity == Severity.MEDIUM
    assert "SS-LISTEN-8080-tcp" in by_rule
    # 22/tcp and 80/tcp are expected — no findings for those ports.
    assert "SS-LISTEN-22-tcp" not in by_rule
    assert "SS-LISTEN-80-tcp" not in by_rule
    assert result.extras["listener_count"] >= 5


def test_ss_expected_listeners_suppress() -> None:
    raw = FIXTURE.read_text(encoding="utf-8")
    plugin = SsBaselinePlugin()
    result = plugin.parse(
        raw,
        0,
        scan_id=SCAN_ID,
        host=HOST,
        options={
            "expected_listeners": [
                "22/tcp",
                "80/tcp",
                "443/tcp",
                "5432/tcp",
                "3306/tcp",
                "8080/tcp",
                "68/udp",
                "6379/tcp",
            ]
        },
    )
    assert result.findings == []
