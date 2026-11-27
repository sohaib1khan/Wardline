"""R5 — Fix installed (Trivy) but service/reboot still pending (patch_status)."""

from __future__ import annotations

import re

from wardline.core.models import Category, Finding, PluginResult, Severity, Verdict
from wardline.correlate.rules.base import Rule, RuleOutcome

_UPGRADE = re.compile(
    r"Upgrade\s+(?P<pkg>\S+)\s+to\s+(?P<fixed>\S+)",
    re.I,
)


class R5PatchedNotActive(Rule):
    rule_id = "R5"
    description = "Flag packages with a fix available while restart/reboot is pending."

    def apply(
        self,
        findings: list[Finding],
        *,
        scan_id: str,
        host: str,
        plugin_results: list[PluginResult] | None = None,
    ) -> RuleOutcome:
        del plugin_results
        patch_pending = [
            f
            for f in findings
            if f.plugin == "patch_status"
            and f.rule_id.startswith(("PATCH-REBOOT", "PATCH-SVC-"))
        ]
        if not patch_pending:
            return RuleOutcome(findings=findings, changed=False)

        extras: list[Finding] = []
        for finding in findings:
            if finding.plugin != "trivy" or finding.category != Category.VULNERABILITY:
                continue
            match = _UPGRADE.search(finding.fix_hint or "")
            if not match:
                continue
            pkg = match.group("pkg")
            fixed = match.group("fixed")
            related = [f.id for f in patch_pending]
            new = Finding(
                scan_id=scan_id,
                host=host,
                plugin="correlate",
                rule_id=f"CORR-R5-{pkg}",
                category=Category.PATCHING,
                severity=Severity.MEDIUM,
                title=f"Fix installed but not running yet: {pkg}",
                description=(
                    f"Trivy reports a fixed version ({fixed}) for {pkg}, while "
                    "patch_status indicates a reboot or service restart is still needed."
                ),
                location=pkg,
                evidence=finding.fix_hint,
                fix_hint="Restart affected services or reboot to activate the update.",
                cve_ids=list(finding.cve_ids),
                verdict=Verdict.CONFIRMED,
                verdict_reason="R5: patched package not yet active",
                related=[finding.id, *related],
            )
            extras.append(new)
            finding.related = sorted(set(finding.related) | {new.id})
            for pf in patch_pending:
                pf.related = sorted(set(pf.related) | {new.id, finding.id})

        return RuleOutcome(findings=[*findings, *extras], changed=bool(extras))
