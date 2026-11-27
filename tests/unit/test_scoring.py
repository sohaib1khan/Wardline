"""Unit tests for posture score and summary builders."""

from __future__ import annotations

from wardline.core.models import (
    Category,
    Finding,
    FindingStatus,
    Severity,
    Verdict,
)
from wardline.core.scoring import (
    BASE_SCORE,
    PENALTIES,
    build_scores,
    build_summary,
    compute_posture_score,
)


def _f(
    severity: Severity,
    *,
    status: FindingStatus = FindingStatus.OPEN,
    verdict: Verdict = Verdict.NONE,
    rule_id: str = "R1",
    location: str = "/x",
) -> Finding:
    return Finding(
        scan_id="01ARZ3NDEKTSV4RRFFQ69G5FAV",
        host="lab01.example.internal",
        plugin="test",
        rule_id=rule_id,
        category=Category.HARDENING,
        severity=severity,
        title="t",
        location=location,
        status=status,
        verdict=verdict,
    )


def test_empty_findings_score_100() -> None:
    assert compute_posture_score([]) == BASE_SCORE


def test_penalties_applied() -> None:
    findings = [
        _f(Severity.CRITICAL, rule_id="c1", location="a"),
        _f(Severity.HIGH, rule_id="h1", location="b"),
        _f(Severity.MEDIUM, rule_id="m1", location="c"),
        _f(Severity.LOW, rule_id="l1", location="d"),
        _f(Severity.INFO, rule_id="i1", location="e"),
    ]
    expected = (
        BASE_SCORE
        - PENALTIES[Severity.CRITICAL]
        - PENALTIES[Severity.HIGH]
        - PENALTIES[Severity.MEDIUM]
        - PENALTIES[Severity.LOW]
        - PENALTIES[Severity.INFO]
    )
    assert compute_posture_score(findings) == expected


def test_floor_at_zero() -> None:
    findings = [_f(Severity.CRITICAL, rule_id=f"c{i}", location=str(i)) for i in range(20)]
    assert compute_posture_score(findings) == 0


def test_false_positives_and_accepted_excluded() -> None:
    findings = [
        _f(Severity.CRITICAL, rule_id="a", location="1"),
        _f(
            Severity.CRITICAL,
            rule_id="b",
            location="2",
            verdict=Verdict.LIKELY_FALSE_POSITIVE,
        ),
        _f(
            Severity.CRITICAL,
            rule_id="c",
            location="3",
            status=FindingStatus.ACCEPTED_RISK,
        ),
        _f(
            Severity.CRITICAL,
            rule_id="d",
            location="4",
            status=FindingStatus.RESOLVED,
        ),
    ]
    assert compute_posture_score(findings) == BASE_SCORE - PENALTIES[Severity.CRITICAL]


def test_build_summary_excludes_false_positives() -> None:
    findings = [
        _f(Severity.HIGH, rule_id="a", location="1"),
        _f(
            Severity.HIGH,
            rule_id="b",
            location="2",
            verdict=Verdict.LIKELY_FALSE_POSITIVE,
        ),
        _f(Severity.INFO, rule_id="c", location="3"),
    ]
    summary = build_summary(findings)
    assert summary.total_findings == 2
    assert summary.by_severity.high == 1
    assert summary.by_severity.info == 1
    assert summary.likely_false_positives == 1
    assert summary.open_findings == 2


def test_build_scores_includes_lynis() -> None:
    scores = build_scores([_f(Severity.LOW, rule_id="x", location="y")], lynis_hardening_index=64)
    assert scores.posture == BASE_SCORE - 1
    assert scores.lynis_hardening_index == 64
