"""Fleet scan — run profiles against many SSH hosts with a concurrency limit."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from pathlib import Path

from wardline.backends.ssh import SSHBackend
from wardline.core.config import WardlineConfig, default_config
from wardline.core.engine import ScanRunOutcome, run_scan
from wardline.core.hosts import HostInventory, HostRecord, known_hosts_path
from wardline.vault.store import VaultStore


@dataclass(slots=True)
class FleetHostResult:
    host_name: str
    ok: bool
    outcome: ScanRunOutcome | None = None
    error: str = ""


@dataclass(slots=True)
class FleetScanResult:
    results: list[FleetHostResult] = field(default_factory=list)

    @property
    def ok_count(self) -> int:
        return sum(1 for r in self.results if r.ok)

    @property
    def fail_count(self) -> int:
        return sum(1 for r in self.results if not r.ok)


async def run_fleet_scan(
    inventory: HostInventory,
    *,
    profile: str = "quick",
    plugin_names: list[str] | None = None,
    host_names: list[str] | None = None,
    config: WardlineConfig | None = None,
    concurrency: int | None = None,
    save: bool = True,
    vault: VaultStore | None = None,
    known_hosts: Path | None = None,
) -> FleetScanResult:
    """Scan selected (or all) hosts from the inventory concurrently."""
    cfg = config or default_config()
    limit = concurrency or inventory.fleet_concurrency
    targets = (
        [inventory.get(n) for n in host_names] if host_names else list(inventory.hosts)
    )
    if not targets:
        return FleetScanResult()

    sem = asyncio.Semaphore(limit)
    store = vault or VaultStore()
    kh = known_hosts if known_hosts is not None else known_hosts_path()
    results: list[FleetHostResult] = []

    async def _one(record: HostRecord) -> FleetHostResult:
        async with sem:
            backend = SSHBackend(record, known_hosts=kh)
            try:
                outcome = await run_scan(
                    backend,
                    profile=profile,
                    plugin_names=plugin_names,
                    config=cfg,
                )
                if save and cfg.vault.auto_save:
                    previous = store.recent_for_host(outcome.scan.host.hostname, limit=5)
                    store.save(
                        outcome.scan,
                        raw_by_plugin=outcome.raw_by_plugin,
                        previous_scans=previous,
                    )
                return FleetHostResult(host_name=record.name, ok=True, outcome=outcome)
            except Exception as exc:
                return FleetHostResult(host_name=record.name, ok=False, error=str(exc))
            finally:
                await backend.close()

    gathered = await asyncio.gather(*[_one(t) for t in targets])
    results.extend(gathered)
    return FleetScanResult(results=results)
