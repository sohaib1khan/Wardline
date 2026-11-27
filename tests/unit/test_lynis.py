"""Parser tests for Lynis."""

from __future__ import annotations

from pathlib import Path

from wardline.core.models import Severity
from wardline.plugins.lynis import LynisPlugin

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "lynis"
SCAN_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
HOST = "lab01.example.internal"


def test_lynis_report_parsing() -> None:
    report = (FIXTURES / "report.dat").read_text(encoding="utf-8")
    outdated = (FIXTURES / "outdated_stdout.txt").read_text(encoding="utf-8")
    raw = outdated + "\n" + report
    result = LynisPlugin().parse(raw, 0, scan_id=SCAN_ID, host=HOST)

    assert result.extras["hardening_index"] == 64
    by_id = {f.rule_id: f for f in result.findings}
    assert by_id["SSH-7408"].severity == Severity.MEDIUM
    assert by_id["AUTH-9282"].severity == Severity.MEDIUM  # important suggestion
    assert by_id["BOOT-5122"].severity == Severity.LOW
    assert by_id["LYNIS-OUTDATED"].severity == Severity.INFO


def test_lynis_missing_report_marker() -> None:
    raw = "# wardline: missing report file /var/log/lynis-report.dat"
    result = LynisPlugin().parse(raw, 0, scan_id=SCAN_ID, host=HOST)
    assert any(f.rule_id == "LYNIS-NO-REPORT" for f in result.findings)
