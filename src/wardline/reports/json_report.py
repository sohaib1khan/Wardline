"""JSON report helpers."""

from __future__ import annotations

import json

from wardline.core.models import Scan
from wardline.reports.redact import redact_scan


def render_json(scan: Scan, *, redact: bool = False) -> str:
    payload = redact_scan(scan) if redact else scan
    return json.dumps(payload.model_dump(mode="json"), indent=2) + "\n"
