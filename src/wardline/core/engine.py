"""Scan orchestrator — runs plugins through a Backend and emits events."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from ulid import ULID

from wardline import __version__
from wardline.backends.base import Backend, CommandResult
from wardline.core.config import WardlineConfig, default_config
from wardline.core.events import Event, EventBus, EventKind
from wardline.core.models import (
    BackendKind,
    Finding,
    PluginResult,
    PluginStatus,
    Scan,
    Severity,
)
from wardline.core.profiles import resolve_plugin_names
from wardline.core.scoring import build_scores, build_summary
from wardline.correlate import apply_correlation
from wardline.plugins.base import Plugin, PluginRegistry, get_registry

SKIP_NEEDS_ROOT = "needs root — re-run with sudo"
SKIP_NOT_INSTALLED = "tool not installed"
SKIP_DENYLISTED = "tool version is denylisted"
SKIP_LOW_RAM = "insufficient RAM for this plugin"
SKIP_UNKNOWN_PLUGIN = "plugin not registered"


@dataclass(slots=True)
class PluginRunOutcome:
    result: PluginResult
    findings: list[Finding] = field(default_factory=list)
    raw_output: str = ""


@dataclass(slots=True)
class ScanRunOutcome:
    scan: Scan
    raw_by_plugin: dict[str, str] = field(default_factory=dict)


async def run_scan(
    backend: Backend,
    *,
    profile: str = "quick",
    plugin_names: list[str] | None = None,
    config: WardlineConfig | None = None,
    bus: EventBus | None = None,
    registry: PluginRegistry | None = None,
    tags: list[str] | None = None,
    plugin_options: dict[str, dict[str, Any]] | None = None,
) -> ScanRunOutcome:
    """Run an ordered list of plugins and return a Scan object."""
    cfg = config or default_config()
    bus = bus or EventBus()
    registry = registry or get_registry()
    names = resolve_plugin_names(profile=profile, plugins=plugin_names)
    overrides = plugin_options or {}

    host_info = await backend.host_info()
    scan_id = str(ULID())
    started = datetime.now(UTC)

    await bus.publish(
        Event(
            kind=EventKind.SCAN_STARTED,
            message=f"profile={profile}",
            data={"scan_id": scan_id, "plugins": names, "host": host_info.hostname},
        )
    )

    plugin_results: list[PluginResult] = []
    findings: list[Finding] = []
    raw_by_plugin: dict[str, str] = {}
    lynis_index: int | None = None

    for name in names:
        if name not in registry:
            plugin_results.append(
                PluginResult(
                    plugin=name,
                    status=PluginStatus.UNAVAILABLE,
                    skip_reason=SKIP_UNKNOWN_PLUGIN,
                )
            )
            continue

        plugin = registry.get(name)
        options = _options_for_plugin(plugin.name, cfg)
        if plugin.name in overrides:
            options = {**options, **overrides[plugin.name]}
        outcome = await run_plugin(
            plugin,
            backend,
            scan_id=scan_id,
            host=host_info.hostname,
            bus=bus,
            options=options,
        )
        plugin_results.append(outcome.result)
        findings.extend(outcome.findings)
        if outcome.raw_output:
            raw_by_plugin[plugin.name] = outcome.raw_output
        idx = outcome.result.extras.get("hardening_index")
        if isinstance(idx, int):
            lynis_index = idx

    correlated = apply_correlation(
        findings,
        scan_id=scan_id,
        host=host_info.hostname,
        plugin_results=plugin_results,
    )
    findings = correlated.findings

    finished = datetime.now(UTC)
    summary = build_summary(findings)
    scores = build_scores(findings, lynis_hardening_index=lynis_index)
    scan = Scan(
        id=scan_id,
        wardline_version=__version__,
        started_at=started,
        finished_at=finished,
        profile=profile if not plugin_names else "custom",
        backend=backend.kind if isinstance(backend.kind, BackendKind) else BackendKind.LOCAL,
        host=host_info,
        plugin_results=plugin_results,
        findings=findings,
        summary=summary,
        scores=scores,
        tags=list(tags or []),
    )

    await bus.publish(
        Event(
            kind=EventKind.SCAN_FINISHED,
            message=f"posture={scores.posture}",
            data={
                "scan_id": scan_id,
                "findings": summary.total_findings,
                "posture": scores.posture,
            },
        )
    )
    return ScanRunOutcome(scan=scan, raw_by_plugin=raw_by_plugin)


def _options_for_plugin(name: str, cfg: WardlineConfig) -> dict[str, Any]:
    if name == "ss_baseline":
        return {"expected_listeners": list(cfg.scan.ss.expected_listeners)}
    if name == "clamav":
        return {
            "paths": list(cfg.scan.clamav.paths),
            "min_ram_mb": cfg.scan.clamav.min_ram_mb,
        }
    if name == "nmap":
        allowed = list(cfg.scan.nmap.allowed_targets)
        return {
            "allowed_targets": allowed,
            "targets": list(allowed),
        }
    if name == "chkrootkit":
        return {"false_positives": list(cfg.scan.false_positives.chkrootkit)}
    return {}


async def run_plugin(
    plugin: Plugin,
    backend: Backend,
    *,
    scan_id: str,
    host: str,
    bus: EventBus | None = None,
    options: dict[str, Any] | None = None,
    timeout: float | None = None,
) -> PluginRunOutcome:
    """Detect, guard, run, and parse a single plugin."""
    bus = bus or EventBus()
    options = options or {}
    effective_timeout = timeout if timeout is not None else plugin.default_timeout

    await bus.publish(Event(kind=EventKind.PLUGIN_STARTED, plugin=plugin.name, message="started"))

    detect = await plugin.detect(backend)
    if detect.denylisted or plugin.check_denylist(detect.version):
        reason = detect.denylist_reason or plugin.check_denylist(detect.version) or SKIP_DENYLISTED
        denylist_findings = plugin.denylist_findings(
            scan_id=scan_id, host=host, version=detect.version
        )
        for finding in denylist_findings:
            await bus.publish(
                Event(
                    kind=EventKind.FINDING,
                    plugin=plugin.name,
                    message=finding.title,
                    data={"finding_id": finding.id, "severity": finding.severity.value},
                )
            )
        outcome = PluginRunOutcome(
            result=PluginResult(
                plugin=plugin.name,
                tool_version=detect.version,
                status=PluginStatus.UNAVAILABLE,
                skip_reason=reason,
            ),
            findings=denylist_findings,
        )
        await bus.publish(
            Event(
                kind=EventKind.PLUGIN_SKIPPED,
                plugin=plugin.name,
                message=reason,
                data={"status": PluginStatus.UNAVAILABLE.value},
            )
        )
        await _emit_finished(bus, plugin, outcome)
        return outcome

    if not detect.installed:
        return await _skip(plugin, bus, SKIP_NOT_INSTALLED, status=PluginStatus.UNAVAILABLE)

    if plugin.needs_root and not backend.is_root():
        return await _skip(plugin, bus, SKIP_NEEDS_ROOT)

    if plugin.min_ram_mb > 0:
        ram = await backend.total_ram_mb()
        if ram is not None and ram < plugin.min_ram_mb:
            return await _skip(
                plugin,
                bus,
                f"{SKIP_LOW_RAM} ({ram} MiB < {plugin.min_ram_mb} MiB)",
            )

    commands = plugin.build_commands(backend, options)
    if not commands:
        return await _skip(plugin, bus, "plugin produced no commands")

    started = time.monotonic()
    results: list[CommandResult] = []
    timed_out = False

    async def on_line(stream: str, line: str) -> None:
        await bus.publish(
            Event(
                kind=EventKind.OUTPUT_LINE,
                plugin=plugin.name,
                stream=stream,
                message=line,
            )
        )

    for argv in commands:
        result = await backend.run(
            argv,
            timeout=effective_timeout,
            needs_root=plugin.needs_root,
            on_line=on_line,
        )
        results.append(result)
        if result.timed_out:
            timed_out = True
            break

    duration = time.monotonic() - started
    raw = await plugin.collect_raw_output(backend, results)
    exit_code = results[-1].exit_code if results else -1

    if timed_out:
        outcome = PluginRunOutcome(
            result=PluginResult(
                plugin=plugin.name,
                tool_version=detect.version,
                status=PluginStatus.TIMED_OUT,
                duration_seconds=duration,
                exit_code=exit_code,
                skip_reason="timed out",
            ),
            raw_output=raw,
        )
        await _emit_finished(bus, plugin, outcome)
        return outcome

    status = plugin.interpret_exit_code(exit_code)
    parsed = plugin.parse(raw, exit_code, scan_id=scan_id, host=host, options=options)
    if parsed.findings and status == PluginStatus.OK:
        status = PluginStatus.FINDINGS

    for finding in parsed.findings:
        await bus.publish(
            Event(
                kind=EventKind.FINDING,
                plugin=plugin.name,
                message=finding.title,
                data={"finding_id": finding.id, "severity": finding.severity.value},
            )
        )

    outcome = PluginRunOutcome(
        result=PluginResult(
            plugin=plugin.name,
            tool_version=detect.version,
            status=status,
            duration_seconds=duration,
            exit_code=exit_code,
            extras=parsed.extras,
        ),
        findings=parsed.findings,
        raw_output=raw,
    )
    await _emit_finished(bus, plugin, outcome)
    return outcome


async def _skip(
    plugin: Plugin,
    bus: EventBus,
    reason: str,
    *,
    status: PluginStatus = PluginStatus.SKIPPED,
) -> PluginRunOutcome:
    outcome = PluginRunOutcome(
        result=PluginResult(
            plugin=plugin.name,
            status=status,
            skip_reason=reason,
        )
    )
    await bus.publish(
        Event(
            kind=EventKind.PLUGIN_SKIPPED,
            plugin=plugin.name,
            message=reason,
            data={"status": status.value},
        )
    )
    await _emit_finished(bus, plugin, outcome)
    return outcome


async def _emit_finished(bus: EventBus, plugin: Plugin, outcome: PluginRunOutcome) -> None:
    await bus.publish(
        Event(
            kind=EventKind.PLUGIN_FINISHED,
            plugin=plugin.name,
            message=outcome.result.status.value,
            data={
                "status": outcome.result.status.value,
                "exit_code": outcome.result.exit_code,
                "findings": len(outcome.findings),
                "duration_seconds": outcome.result.duration_seconds,
                "skip_reason": outcome.result.skip_reason,
            },
        )
    )


_SEVERITY_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


def fail_on_triggered(scan: Scan, fail_on: Severity | None) -> bool:
    """Return True if any headline finding meets or exceeds fail_on."""
    if fail_on is None:
        return False
    threshold = _SEVERITY_RANK[fail_on]
    for finding in scan.findings:
        if finding.verdict.value == "likely_false_positive":
            continue
        if _SEVERITY_RANK.get(finding.severity, 0) >= threshold:
            return True
    return False
