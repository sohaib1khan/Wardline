"""R2 — Changed binary (AIDE/rkhunter) vs package verification."""

from __future__ import annotations

import re

from wardline.core.models import Category, Finding, PluginResult, PluginStatus, Severity, Verdict
from wardline.correlate.rules.base import Rule, RuleOutcome

_PATH_RE = re.compile(r"(/(?:usr|bin|sbin|lib|etc|opt|var|home|boot)[\w./+-]*)")


class R2ChangedBinary(Rule):
    rule_id = "R2"
    description = "Correlate integrity changes with pkg_verify; lock baseline if dirty."

    def apply(
        self,
        findings: list[Finding],
        *,
        scan_id: str,
        host: str,
        plugin_results: list[PluginResult] | None = None,
    ) -> RuleOutcome:
        dirty_paths = {
            f.location
            for f in findings
            if f.plugin == "pkg_verify" and f.location.startswith("/")
        }
        verify_ran = _pkg_verify_ran(findings, plugin_results)

        changed = False
        locked = False
        lock_reason = ""
        extras: list[Finding] = []

        for finding in findings:
            path = _changed_path(finding)
            if not path:
                continue

            if path in dirty_paths:
                finding.verdict = Verdict.CONFIRMED
                finding.verdict_reason = (
                    f"Package verification reports a mismatch for {path}."
                )
                related_ids = [
                    f.id for f in findings if f.plugin == "pkg_verify" and f.location == path
                ]
                finding.related = sorted(set(finding.related) | set(related_ids))
                extras.append(
                    Finding(
                        scan_id=scan_id,
                        host=host,
                        plugin="correlate",
                        rule_id=f"CORR-R2-TAMPER-{path}",
                        category=Category.INTEGRITY,
                        severity=Severity.CRITICAL,
                        title=f"Binary differs from package — possible tampering: {path}",
                        description=(
                            "Integrity scanner reported a change and pkg_verify confirms "
                            "the file no longer matches the package database. "
                            "Do not re-baseline until investigated."
                        ),
                        location=path,
                        evidence=finding.evidence or path,
                        fix_hint=(
                            "Investigate tampering; Guarded Baseline is locked for this path."
                        ),
                        verdict=Verdict.CONFIRMED,
                        verdict_reason="R2: dirty package verification",
                        related=[finding.id, *related_ids],
                    )
                )
                locked = True
                lock_reason = f"pkg_verify dirty for {path}"
                changed = True
            elif verify_ran:
                finding.verdict = Verdict.NEEDS_REVIEW
                finding.verdict_reason = (
                    "Matches package DB, probably an update — review before Guarded Baseline."
                )
                changed = True
            else:
                finding.verdict = Verdict.NEEDS_REVIEW
                finding.verdict_reason = (
                    "No package-verify result available for this path yet."
                )
                changed = True

        return RuleOutcome(
            findings=[*findings, *extras],
            changed=changed or bool(extras),
            baseline_locked=locked,
            baseline_lock_reason=lock_reason,
        )


def _pkg_verify_ran(
    findings: list[Finding],
    plugin_results: list[PluginResult] | None,
) -> bool:
    if any(f.plugin == "pkg_verify" for f in findings):
        return True
    if not plugin_results:
        return False
    for pr in plugin_results:
        if pr.plugin == "pkg_verify" and pr.status in {
            PluginStatus.OK,
            PluginStatus.FINDINGS,
        }:
            return True
    return False


def _changed_path(finding: Finding) -> str | None:
    if (
        finding.plugin == "aide"
        and finding.rule_id.startswith("AIDE-CHANGED-")
        and finding.location.startswith("/")
    ):
        return finding.location
    if finding.plugin == "rkhunter" and finding.rule_id == "RKH-FILE-CHANGED":
        if finding.location.startswith("/"):
            return finding.location
        for text in (finding.evidence, finding.title, finding.description):
            match = _PATH_RE.search(text or "")
            if match:
                return match.group(1).rstrip(":")
    return None
