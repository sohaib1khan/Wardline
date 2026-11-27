"""Generate the plugin capability matrix markdown from registry metadata."""

from __future__ import annotations

from pathlib import Path

from wardline.core.models import BackendKind
from wardline.plugins.base import PluginRegistry, get_registry

HEADER = """# Capability matrix

Generated from plugin metadata (`wardline.plugins`). Re-run:

```bash
uv run wardline docker matrix
```

Levels: **full** · **partial** (see note) · **unavailable**.

| Plugin | Local | Docker | SSH |
|---|---|---|---|
"""


def render_capability_matrix(registry: PluginRegistry | None = None) -> str:
    reg = registry or get_registry()
    lines = [HEADER.rstrip("\n")]
    plugins = sorted(
        reg.list(include_hidden=False),
        key=lambda p: p.display_name.lower(),
    )
    for plugin in plugins:
        cells = [plugin.display_name]
        for kind in (BackendKind.LOCAL, BackendKind.DOCKER, BackendKind.SSH):
            cap = plugin.capabilities.get(kind)
            if cap is None:
                cells.append("—")
                continue
            cell = cap.level.value
            note = (cap.note or "").strip()
            # Notes sometimes repeat the level ("partial — …"); strip that prefix.
            for prefix in (f"{cap.level.value} — ", f"{cap.level.value}/", f"{cap.level.value} "):
                if note.lower().startswith(prefix.lower()):
                    note = note[len(prefix) :].strip()
                    break
            if note and note.lower() != cap.level.value:
                cell = f"{cell} — {note}"
            cells.append(cell)
        lines.append("| " + " | ".join(cells) + " |")
    lines.append("")
    return "\n".join(lines)


def write_capability_matrix(
    path: Path | None = None,
    *,
    registry: PluginRegistry | None = None,
) -> Path:
    # parents: core -> wardline -> src -> repo root
    target = path or Path(__file__).resolve().parents[3] / "docs" / "capability-matrix.md"
    text = render_capability_matrix(registry)
    if not text.endswith("\n"):
        text += "\n"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8")
    return target
