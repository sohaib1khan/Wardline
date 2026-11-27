"""Wardline posture score.

Formula (easy to tune — keep weights in PENALTIES):

* Start at ``BASE_SCORE`` (100).
* For each finding that is still open for scoring (status is ``open``,
  verdict is not ``likely_false_positive``), subtract the severity penalty.
* ``info`` findings do not affect the score.
* ``accepted_risk`` and ``resolved`` findings do not affect the score.
* Floor at 0.

Shown next to (not instead of) the Lynis hardening index when available.
"""

from __future__ import annotations

from collections.abc import Iterable

from wardline.core.models import (
    CategoryCounts,
    Finding,
    FindingStatus,
    ScanScores,
    ScanSummary,
    Severity,
    SeverityCounts,
    Verdict,
)

BASE_SCORE = 100

# Points subtracted per open finding of that severity.
PENALTIES: dict[Severity, int] = {
    Severity.CRITICAL: 15,
    Severity.HIGH: 7,
    Severity.MEDIUM: 3,
    Severity.LOW: 1,
    Severity.INFO: 0,
}


def finding_counts_toward_score(finding: Finding) -> bool:
    """Return True if this finding should reduce the posture score."""
    if finding.status != FindingStatus.OPEN:
        return False
    return finding.verdict != Verdict.LIKELY_FALSE_POSITIVE


def finding_counts_in_headline(finding: Finding) -> bool:
    """Headline summary counts exclude likely false positives."""
    return finding.verdict != Verdict.LIKELY_FALSE_POSITIVE


def compute_posture_score(findings: Iterable[Finding]) -> int:
    """Compute the Wardline posture score from a list of findings."""
    score = BASE_SCORE
    for finding in findings:
        if not finding_counts_toward_score(finding):
            continue
        score -= PENALTIES.get(finding.severity, 0)
    return max(0, score)


def build_summary(findings: Iterable[Finding]) -> ScanSummary:
    """Build headline summary counts (excluding likely_false_positive)."""
    by_severity = SeverityCounts()
    by_category = CategoryCounts()
    total = 0
    open_count = 0
    fp_count = 0

    for finding in findings:
        if finding.verdict == Verdict.LIKELY_FALSE_POSITIVE:
            fp_count += 1
            continue

        total += 1
        sev_field = finding.severity.value
        setattr(by_severity, sev_field, getattr(by_severity, sev_field) + 1)

        cat_field = finding.category.value
        setattr(by_category, cat_field, getattr(by_category, cat_field) + 1)

        if finding.status == FindingStatus.OPEN:
            open_count += 1

    return ScanSummary(
        by_severity=by_severity,
        by_category=by_category,
        total_findings=total,
        open_findings=open_count,
        likely_false_positives=fp_count,
    )


def build_scores(
    findings: Iterable[Finding],
    *,
    lynis_hardening_index: int | None = None,
) -> ScanScores:
    return ScanScores(
        posture=compute_posture_score(findings),
        lynis_hardening_index=lynis_hardening_index,
    )
