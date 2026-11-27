"""Run correlation rules after all plugins finish."""

from __future__ import annotations

from dataclasses import dataclass, field

from wardline.core.models import Finding, PluginResult
from wardline.correlate.rules import ALL_RULES


@dataclass(slots=True)
class CorrelationResult:
    findings: list[Finding]
    baseline_locked: bool = False
    baseline_lock_reasons: list[str] = field(default_factory=list)
    rules_fired: list[str] = field(default_factory=list)


def apply_correlation(
    findings: list[Finding],
    *,
    scan_id: str,
    host: str,
    plugin_results: list[PluginResult] | None = None,
) -> CorrelationResult:
    """Apply R1-R7 in order. Mutates finding verdicts; may append findings."""
    working = list(findings)
    baseline_locked = False
    lock_reasons: list[str] = []
    fired: list[str] = []

    for rule in ALL_RULES:
        before = len(working)
        outcome = rule.apply(
            working,
            scan_id=scan_id,
            host=host,
            plugin_results=plugin_results,
        )
        working = outcome.findings
        if outcome.changed or len(working) != before:
            fired.append(rule.rule_id)
        if outcome.baseline_locked:
            baseline_locked = True
            if outcome.baseline_lock_reason:
                lock_reasons.append(outcome.baseline_lock_reason)

    return CorrelationResult(
        findings=working,
        baseline_locked=baseline_locked,
        baseline_lock_reasons=lock_reasons,
        rules_fired=fired,
    )
