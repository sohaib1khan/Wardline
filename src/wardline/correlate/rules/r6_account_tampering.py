"""R6 — AIDE passwd/shadow change + new persistence account/key."""

from __future__ import annotations

from wardline.core.models import Category, Finding, PluginResult, Severity, Verdict
from wardline.correlate.rules.base import Rule, RuleOutcome

_ACCOUNT_PATHS = ("/etc/passwd", "/etc/shadow", "/etc/sudoers")


class R6AccountTampering(Rule):
    rule_id = "R6"
    description = "Integrity change on account files plus new user/key → critical."

    def apply(
        self,
        findings: list[Finding],
        *,
        scan_id: str,
        host: str,
        plugin_results: list[PluginResult] | None = None,
    ) -> RuleOutcome:
        del plugin_results
        aide_hits = [
            f
            for f in findings
            if f.plugin == "aide"
            and f.rule_id.startswith("AIDE-CHANGED-")
            and any(f.location == p or f.location.startswith(p) for p in _ACCOUNT_PATHS)
        ]
        pers_hits = [
            f
            for f in findings
            if f.plugin == "persistence"
            and (
                f.rule_id.startswith("PERS-USER-")
                or f.rule_id.startswith("PERS-KEY-")
                or f.rule_id.startswith("PERS-UID0-")
            )
        ]
        if not aide_hits or not pers_hits:
            return RuleOutcome(findings=findings, changed=False)

        related = [f.id for f in aide_hits + pers_hits]
        paths = ", ".join(sorted({f.location for f in aide_hits}))
        actors = ", ".join(sorted({f.location for f in pers_hits}))
        new = Finding(
            scan_id=scan_id,
            host=host,
            plugin="correlate",
            rule_id="CORR-R6-ACCOUNT",
            category=Category.PERSISTENCE,
            severity=Severity.CRITICAL,
            title="Possible unauthorized account activity",
            description=(
                f"AIDE reported changes to {paths} and persistence detected "
                f"new account/key activity ({actors})."
            ),
            location=paths,
            evidence=f"aide={paths}; persistence={actors}",
            fix_hint="Investigate new accounts/keys before trusting the host.",
            verdict=Verdict.CONFIRMED,
            verdict_reason="R6: account file change + new persistence",
            related=related,
        )
        for f in aide_hits + pers_hits:
            f.related = sorted(set(f.related) | {new.id})
            f.verdict = Verdict.CONFIRMED
            f.verdict_reason = "Correlated with possible unauthorized account (R6)."

        return RuleOutcome(findings=[*findings, new], changed=True)
