"""Diff two scans of the same host by stable Finding id."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum

from wardline.core.models import Finding, Scan


class DiffKind(StrEnum):
    NEW = "new"
    RESOLVED = "resolved"
    UNCHANGED = "unchanged"
    CHANGED = "changed"


@dataclass(slots=True)
class FindingDiff:
    kind: DiffKind
    finding_id: str
    before: Finding | None = None
    after: Finding | None = None
    changes: list[str] = field(default_factory=list)


@dataclass(slots=True)
class ScanDiff:
    host: str
    a_id: str
    b_id: str
    items: list[FindingDiff]

    @property
    def new_count(self) -> int:
        return sum(1 for i in self.items if i.kind == DiffKind.NEW)

    @property
    def resolved_count(self) -> int:
        return sum(1 for i in self.items if i.kind == DiffKind.RESOLVED)

    @property
    def changed_count(self) -> int:
        return sum(1 for i in self.items if i.kind == DiffKind.CHANGED)


def diff_scans(a: Scan, b: Scan) -> ScanDiff:
    """Compare scan A (older/baseline) to scan B (newer)."""
    if a.host.hostname != b.host.hostname:
        # Still allow, but note host mismatch in changes of a synthetic item.
        pass

    map_a = {f.id: f for f in a.findings}
    map_b = {f.id: f for f in b.findings}
    items: list[FindingDiff] = []

    for fid, finding_b in map_b.items():
        if fid not in map_a:
            items.append(FindingDiff(kind=DiffKind.NEW, finding_id=fid, after=finding_b))
            continue
        finding_a = map_a[fid]
        changes: list[str] = []
        if finding_a.severity != finding_b.severity:
            changes.append(f"severity {finding_a.severity.value} → {finding_b.severity.value}")
        if finding_a.verdict != finding_b.verdict:
            changes.append(f"verdict {finding_a.verdict.value} → {finding_b.verdict.value}")
        if finding_a.status != finding_b.status:
            changes.append(f"status {finding_a.status.value} → {finding_b.status.value}")
        kind = DiffKind.CHANGED if changes else DiffKind.UNCHANGED
        items.append(
            FindingDiff(
                kind=kind,
                finding_id=fid,
                before=finding_a,
                after=finding_b,
                changes=changes,
            )
        )

    for fid, finding_a in map_a.items():
        if fid not in map_b:
            items.append(FindingDiff(kind=DiffKind.RESOLVED, finding_id=fid, before=finding_a))

    order = {
        DiffKind.NEW: 0,
        DiffKind.CHANGED: 1,
        DiffKind.RESOLVED: 2,
        DiffKind.UNCHANGED: 3,
    }
    items.sort(key=lambda i: (order[i.kind], i.finding_id))
    return ScanDiff(host=b.host.hostname, a_id=a.id, b_id=b.id, items=items)
