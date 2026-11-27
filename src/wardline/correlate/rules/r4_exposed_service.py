"""R4 — Merge ss unexplained listener with Nmap open port on the same port."""

from __future__ import annotations

import re

from wardline.core.models import Finding, PluginResult, Verdict
from wardline.correlate.rules.base import Rule, RuleOutcome

_SS_PORT = re.compile(r"SS-LISTEN-(?P<port>\d+)-(?P<proto>\w+)")
_NMAP_PORT = re.compile(r"NMAP-PORT-(?P<port>\d+)-(?P<proto>\w+)")


class R4ExposedService(Rule):
    rule_id = "R4"
    description = "Combine ss + nmap evidence for the same listening port."

    def apply(
        self,
        findings: list[Finding],
        *,
        scan_id: str,
        host: str,
        plugin_results: list[PluginResult] | None = None,
    ) -> RuleOutcome:
        del scan_id, host, plugin_results
        ss_by_key: dict[tuple[str, str], Finding] = {}
        nmap_by_key: dict[tuple[str, str], Finding] = {}

        for finding in findings:
            if finding.plugin == "ss_baseline":
                match = _SS_PORT.fullmatch(finding.rule_id)
                if match:
                    ss_by_key[(match.group("port"), match.group("proto"))] = finding
            elif finding.plugin == "nmap":
                match = _NMAP_PORT.fullmatch(finding.rule_id)
                if match:
                    nmap_by_key[(match.group("port"), match.group("proto"))] = finding

        changed = False
        for key, ss_f in ss_by_key.items():
            nmap_f = nmap_by_key.get(key)
            if not nmap_f:
                continue
            port, proto = key
            merged_evidence = (
                f"[ss]\n{ss_f.evidence}\n\n[nmap]\n{nmap_f.evidence or nmap_f.title}"
            )
            ss_f.evidence = merged_evidence[:4000]
            ss_f.description = (
                f"Unexplained listener {port}/{proto} also seen open by Nmap. "
                f"{ss_f.description}"
            ).strip()
            ss_f.related = sorted(set(ss_f.related) | {nmap_f.id})
            ss_f.verdict = Verdict.CONFIRMED
            ss_f.verdict_reason = "Corroborated by Nmap open-port scan (R4)."
            nmap_f.related = sorted(set(nmap_f.related) | {ss_f.id})
            nmap_f.verdict = Verdict.NEEDS_REVIEW
            nmap_f.verdict_reason = (
                f"Merged into ss_baseline finding for {port}/{proto} (R4)."
            )
            changed = True

        return RuleOutcome(findings=findings, changed=changed)
