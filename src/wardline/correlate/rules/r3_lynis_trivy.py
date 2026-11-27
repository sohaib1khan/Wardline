"""R3 — Link Lynis PKGS-7392 to Trivy vulnerability findings."""

from __future__ import annotations

from wardline.core.models import Category, Finding, PluginResult, Verdict
from wardline.correlate.rules.base import Rule, RuleOutcome

LYNIS_PKG_RULE = "PKGS-7392"


class R3LynisTrivy(Rule):
    rule_id = "R3"
    description = "Lynis package audit suggestion covered by Trivy findings."

    def apply(
        self,
        findings: list[Finding],
        *,
        scan_id: str,
        host: str,
        plugin_results: list[PluginResult] | None = None,
    ) -> RuleOutcome:
        del scan_id, host, plugin_results
        trivy = [
            f
            for f in findings
            if f.plugin == "trivy" and f.category == Category.VULNERABILITY and f.cve_ids
        ]
        if not trivy:
            return RuleOutcome(findings=findings, changed=False)

        changed = False
        related_ids = [f.id for f in trivy]
        for finding in findings:
            if finding.plugin != "lynis" or finding.rule_id != LYNIS_PKG_RULE:
                continue
            finding.verdict = Verdict.NEEDS_REVIEW
            finding.verdict_reason = (
                "Covered by Trivy vulnerability findings — see related CVEs."
            )
            finding.related = sorted(set(finding.related) | set(related_ids))
            for tv in trivy:
                tv.related = sorted(set(tv.related) | {finding.id})
            changed = True

        return RuleOutcome(findings=findings, changed=changed)
