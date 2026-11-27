"""R1 — Nmap/vulners CVE backport check against Trivy."""

from __future__ import annotations

from wardline.core.models import Category, Finding, PluginResult, Verdict
from wardline.correlate.rules.base import Rule, RuleOutcome


class R1BackportCheck(Rule):
    rule_id = "R1"
    description = "Mark Nmap CVE hits as FP when Trivy shows the distro already fixed them."

    def apply(
        self,
        findings: list[Finding],
        *,
        scan_id: str,
        host: str,
        plugin_results: list[PluginResult] | None = None,
    ) -> RuleOutcome:
        del scan_id, host, plugin_results
        trivy_cves = {
            cve
            for f in findings
            if f.plugin == "trivy" and f.category == Category.VULNERABILITY
            for cve in f.cve_ids
        }
        any_trivy = any(f.plugin == "trivy" for f in findings)

        changed = False
        for finding in findings:
            if finding.plugin != "nmap" or finding.category != Category.VULNERABILITY:
                continue
            cves = [c for c in finding.cve_ids if c.startswith("CVE-")]
            if not cves and finding.rule_id.startswith("CVE-"):
                cves = [finding.rule_id]
            if not cves:
                continue

            matched = [c for c in cves if c in trivy_cves]
            if matched:
                finding.verdict = Verdict.CONFIRMED
                finding.verdict_reason = (
                    f"Same CVE(s) still reported by Trivy package scan: {', '.join(matched)}"
                )
                related = [
                    f.id
                    for f in findings
                    if f.plugin == "trivy" and any(c in f.cve_ids for c in matched)
                ]
                finding.related = sorted(set(finding.related) | set(related))
                changed = True
            elif any_trivy:
                # Trivy ran; this CVE is absent → likely distro backport / banner FP.
                finding.verdict = Verdict.LIKELY_FALSE_POSITIVE
                finding.verdict_reason = (
                    "Distro backported the fix; Nmap banner shows the upstream version "
                    "while Trivy does not report this CVE on installed packages."
                )
                changed = True
            else:
                finding.verdict = Verdict.NEEDS_REVIEW
                finding.verdict_reason = (
                    "No Trivy package data available to confirm or dismiss this CVE."
                )
                changed = True

        return RuleOutcome(findings=findings, changed=changed)
