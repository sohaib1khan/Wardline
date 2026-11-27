"""Shared types for correlation rules."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from wardline.core.models import Finding, PluginResult


@dataclass(slots=True)
class RuleOutcome:
    findings: list[Finding]
    changed: bool = False
    baseline_locked: bool = False
    baseline_lock_reason: str = ""
    notes: list[str] = field(default_factory=list)


class Rule(ABC):
    rule_id: str
    description: str = ""

    @abstractmethod
    def apply(
        self,
        findings: list[Finding],
        *,
        scan_id: str,
        host: str,
        plugin_results: list[PluginResult] | None = None,
    ) -> RuleOutcome:
        """Return updated findings list (may mutate verdict fields in place)."""
