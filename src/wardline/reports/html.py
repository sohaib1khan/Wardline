"""Self-contained HTML report renderer (inline CSS, no CDN)."""

from __future__ import annotations

from importlib import resources

from jinja2 import Environment, BaseLoader, select_autoescape

from wardline.core.models import Scan
from wardline.reports.redact import redact_scan


def _load_template() -> str:
    ref = resources.files("wardline.reports.templates").joinpath("report.html.j2")
    return ref.read_text(encoding="utf-8")


_SEV_RANK = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}


def render_html(
    scan: Scan,
    *,
    redact: bool = False,
    previous_scans: list[Scan] | None = None,
) -> str:
    s = redact_scan(scan) if redact else scan
    previous = previous_scans or []
    # Oldest → newest posture trend including current.
    trend_scores = [p.scores.posture for p in reversed(previous[:8])]
    trend_scores.append(s.scores.posture)
    findings = sorted(
        s.findings,
        key=lambda f: (_SEV_RANK.get(f.severity.value, 9), f.plugin, f.title),
    )

    env = Environment(
        loader=BaseLoader(),
        autoescape=select_autoescape(enabled_extensions=("html", "j2")),
    )
    template = env.from_string(_load_template())
    return template.render(scan=s, trend=trend_scores, findings=findings)
