"""Guarded Baseline — refuse AIDE/rkhunter updates until pkg_verify is clean."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

from wardline.backends.base import Backend, CommandResult
from wardline.core.models import Category, Finding, Severity, Verdict
from wardline.plugins.pkg_verify import PkgVerifyPlugin

BaselineTool = Literal["aide", "rkhunter"]

AIDE_INIT_CMD = ["aide", "--init"]
AIDE_INIT_DEBIAN = ["aideinit", "-y", "-f"]
RKH_PROPUPD_CMD = ["rkhunter", "--propupd", "--nocolors"]


@dataclass(slots=True)
class BaselinePlan:
    """Dialog-ready plan for a Guarded Baseline action."""

    tool: BaselineTool
    changed_paths: list[str] = field(default_factory=list)
    dirty_paths: list[str] = field(default_factory=list)
    verify_raw: str = ""
    verify_exit_code: int | None = None
    blocked: bool = False
    block_reason: str = ""
    commands: list[list[str]] = field(default_factory=list)
    critical_finding: Finding | None = None
    notes: list[str] = field(default_factory=list)


@dataclass(slots=True)
class BaselineResult:
    plan: BaselinePlan
    executed: bool = False
    command_results: list[CommandResult] = field(default_factory=list)
    message: str = ""


def baseline_commands(tool: BaselineTool, *, debian_aideinit: bool = False) -> list[list[str]]:
    if tool == "aide":
        return [AIDE_INIT_DEBIAN if debian_aideinit else AIDE_INIT_CMD]
    return [RKH_PROPUPD_CMD]


async def plan_guarded_baseline(
    backend: Backend,
    tool: BaselineTool,
    *,
    scan_id: str = "baseline",
    host: str = "localhost",
    changed_paths: list[str] | None = None,
    debian_aideinit: bool = False,
) -> BaselinePlan:
    """Run package verification and decide whether baselining is allowed.

    Never mutates the system — only plans the action.
    """
    paths = [p for p in (changed_paths or []) if p.startswith("/")]
    verify = PkgVerifyPlugin()
    detect = await verify.detect(backend)
    notes: list[str] = []
    if not detect.installed:
        return BaselinePlan(
            tool=tool,
            changed_paths=paths,
            blocked=True,
            block_reason="Package verification tool (debsums/rpm) is not installed.",
            commands=baseline_commands(tool, debian_aideinit=debian_aideinit),
            notes=["Install debsums (Debian) or use rpm (RHEL) before baselining."],
        )

    options: dict = {}
    if detect.detail == "rpm" or (detect.version or "").startswith("rpm"):
        options["mode"] = "rpm"
    if paths:
        options["files"] = paths

    commands = verify.build_commands(backend, options)
    parts: list[str] = []
    exit_code = 0
    for argv in commands:
        result = await backend.run(argv, timeout=300.0, needs_root=False)
        parts.append(result.stdout)
        parts.append(result.stderr)
        exit_code = result.exit_code

    raw = "\n".join(p for p in parts if p).strip()
    parsed = verify.parse(raw, exit_code, scan_id=scan_id, host=host, options=options)
    dirty = sorted(
        {
            f.location
            for f in parsed.findings
            if f.location.startswith("/")
            and (not paths or f.location in paths or any(f.location.startswith(p) for p in paths))
        }
    )
    # If specific paths requested, only those count as blockers.
    if paths:
        dirty = [p for p in dirty if p in paths]

    plan = BaselinePlan(
        tool=tool,
        changed_paths=paths,
        dirty_paths=dirty,
        verify_raw=raw,
        verify_exit_code=exit_code,
        commands=baseline_commands(tool, debian_aideinit=debian_aideinit),
        notes=notes,
    )

    if dirty:
        plan.blocked = True
        plan.block_reason = (
            "Package verification failed — possible tampering; do not re-baseline."
        )
        plan.critical_finding = Finding(
            scan_id=scan_id,
            host=host,
            plugin="baseline",
            rule_id="BASELINE-BLOCKED-TAMPER",
            category=Category.INTEGRITY,
            severity=Severity.CRITICAL,
            title="Possible tampering — do not re-baseline",
            description=(
                f"Guarded Baseline blocked for {tool}: pkg_verify reported mismatches "
                f"on: {', '.join(dirty)}"
            ),
            location=dirty[0],
            evidence=raw[:2000] or ", ".join(dirty),
            fix_hint="Investigate dirty paths before any AIDE init or rkhunter --propupd.",
            verdict=Verdict.CONFIRMED,
            verdict_reason="Guarded Baseline: dirty package verification",
        )
        return plan

    if paths:
        plan.notes.append(f"Verified {len(paths)} path(s) clean against the package database.")
    else:
        plan.notes.append("Full package verification reported no mismatches.")
    return plan


async def run_guarded_baseline(
    backend: Backend,
    tool: BaselineTool,
    *,
    yes: bool = False,
    scan_id: str = "baseline",
    host: str | None = None,
    changed_paths: list[str] | None = None,
    debian_aideinit: bool = False,
) -> BaselineResult:
    """Plan, optionally confirm, then run the baseline update commands."""
    host_info = await backend.host_info()
    hostname = host or host_info.hostname
    plan = await plan_guarded_baseline(
        backend,
        tool,
        scan_id=scan_id,
        host=hostname,
        changed_paths=changed_paths,
        debian_aideinit=debian_aideinit,
    )
    if plan.blocked:
        return BaselineResult(
            plan=plan,
            executed=False,
            message=plan.block_reason or "Blocked by Guarded Baseline.",
        )
    if not yes:
        return BaselineResult(
            plan=plan,
            executed=False,
            message=(
                "Dry-run only. Re-run with --yes to execute after reviewing the commands."
            ),
        )
    if not backend.is_root():
        return BaselineResult(
            plan=plan,
            executed=False,
            message="Baseline updates require root — re-run with sudo.",
        )

    results: list[CommandResult] = []
    for argv in plan.commands:
        results.append(await backend.run(argv, timeout=1800.0, needs_root=True))

    failed = [r for r in results if r.exit_code not in {0, 1}]
    if failed:
        return BaselineResult(
            plan=plan,
            executed=True,
            command_results=results,
            message=f"{tool} baseline command failed (exit {failed[0].exit_code}).",
        )
    return BaselineResult(
        plan=plan,
        executed=True,
        command_results=results,
        message=f"{tool} baseline updated successfully.",
    )
