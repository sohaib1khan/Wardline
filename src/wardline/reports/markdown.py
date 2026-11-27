"""Markdown report renderer."""

from __future__ import annotations

from wardline.core.models import Scan, Severity
from wardline.reports.redact import redact_scan

_SEV_ORDER = [
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
]


def render_markdown(scan: Scan, *, redact: bool = False) -> str:
    s = redact_scan(scan) if redact else scan
    lines: list[str] = [
        f"# Wardline report — {s.host.hostname}",
        "",
        f"- **Scan ID:** `{s.id}`",
        f"- **Profile:** {s.profile}",
        f"- **Backend:** {s.backend.value}",
        f"- **Started:** {s.started_at.isoformat()}",
        f"- **Finished:** {s.finished_at.isoformat() if s.finished_at else '—'}",
        f"- **Posture score:** {s.scores.posture}",
    ]
    if s.scores.lynis_hardening_index is not None:
        lines.append(f"- **Lynis hardening index:** {s.scores.lynis_hardening_index}")
    if s.tags:
        lines.append(f"- **Tags:** {', '.join(s.tags)}")
    lines.extend(["", "## Summary", ""])
    sev = s.summary.by_severity
    lines.append(
        f"| critical | high | medium | low | info |\n"
        f"|---:|---:|---:|---:|---:|\n"
        f"| {sev.critical} | {sev.high} | {sev.medium} | {sev.low} | {sev.info} |"
    )

    lines.extend(["", "## Plugins", "", "| Plugin | Status | Duration | Exit | Notes |", "|---|---|---:|---:|---|"])
    for pr in s.plugin_results:
        dur = f"{pr.duration_seconds:.1f}s" if pr.duration_seconds is not None else "—"
        exit_code = pr.exit_code if pr.exit_code is not None else "—"
        notes = pr.skip_reason or ""
        lines.append(f"| {pr.plugin} | {pr.status.value} | {dur} | {exit_code} | {notes} |")

    lines.extend(["", "## Findings", ""])
    if not s.findings:
        lines.append("_No findings._")
    else:
        by_sev: dict[Severity, list] = {sev: [] for sev in _SEV_ORDER}
        for finding in s.findings:
            by_sev.setdefault(finding.severity, []).append(finding)
        for severity in _SEV_ORDER:
            group = by_sev.get(severity) or []
            if not group:
                continue
            lines.append(f"### {severity.value}")
            lines.append("")
            for finding in group:
                lines.append(f"#### {finding.title}")
                lines.append("")
                lines.append(f"- **ID:** `{finding.id}`")
                lines.append(f"- **Plugin / rule:** {finding.plugin} / `{finding.rule_id}`")
                lines.append(f"- **Location:** `{finding.location}`")
                if finding.cve_ids:
                    lines.append(f"- **CVEs:** {', '.join(finding.cve_ids)}")
                if finding.verdict.value != "none":
                    lines.append(
                        f"- **Verdict:** {finding.verdict.value}"
                        + (f" — {finding.verdict_reason}" if finding.verdict_reason else "")
                    )
                if finding.description:
                    lines.append(f"- **Description:** {finding.description}")
                if finding.fix_hint:
                    lines.append(f"- **Fix hint:** {finding.fix_hint}")
                if finding.evidence:
                    lines.append("")
                    lines.append("```")
                    lines.append(finding.evidence[:1000])
                    lines.append("```")
                lines.append("")

    lines.append("")
    return "\n".join(lines)
