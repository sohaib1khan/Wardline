"""Local execution backend — async subprocess on the current host."""

from __future__ import annotations

import asyncio
import contextlib
import os
import platform
import shutil
import time
from pathlib import Path

from wardline.backends.base import Backend, CommandResult, LineCallback, merge_env
from wardline.core.distro import detect_distro, kernel_release, machine_arch
from wardline.core.models import BackendKind, HostInfo

NICE_ARGV = ["nice", "-n", "19"]
IONICE_ARGV = ["ionice", "-c", "3"]
MEMINFO_PATH = Path("/proc/meminfo")


def read_total_ram_mb(meminfo_path: Path = MEMINFO_PATH) -> int | None:
    """Parse MemTotal from /proc/meminfo. Returns MiB, or None if unavailable."""
    try:
        text = meminfo_path.read_text(encoding="utf-8")
    except OSError:
        return None
    for line in text.splitlines():
        if line.startswith("MemTotal:"):
            parts = line.split()
            if len(parts) >= 2 and parts[1].isdigit():
                kib = int(parts[1])
                return kib // 1024
    return None


class LocalBackend(Backend):
    kind = BackendKind.LOCAL

    def __init__(self, *, apply_priority: bool = True) -> None:
        self._apply_priority = apply_priority
        self._prefix_cache: list[str] | None = None

    def is_root(self) -> bool:
        return os.geteuid() == 0

    def path(self, host_path: str) -> str:
        return host_path

    def prefix(self) -> list[str]:
        if not self._apply_priority:
            return []
        if self._prefix_cache is not None:
            return list(self._prefix_cache)

        parts: list[str] = []
        if shutil.which("nice"):
            parts.extend(NICE_ARGV)
        if shutil.which("ionice"):
            parts.extend(IONICE_ARGV)
        self._prefix_cache = parts
        return list(parts)

    async def which(self, binary: str) -> str | None:
        return await asyncio.to_thread(shutil.which, binary)

    async def exists(self, path: str) -> bool:
        return await asyncio.to_thread(Path(path).exists)

    async def read_file(self, path: str) -> bytes:
        def _read() -> bytes:
            p = Path(path)
            if not p.is_file():
                raise FileNotFoundError(path)
            return p.read_bytes()

        return await asyncio.to_thread(_read)

    async def total_ram_mb(self) -> int | None:
        return await asyncio.to_thread(read_total_ram_mb)

    async def host_info(self) -> HostInfo:
        distro = await asyncio.to_thread(detect_distro)
        ram = await self.total_ram_mb()
        return HostInfo(
            hostname=platform.node() or "localhost",
            distro=distro.id,
            version=distro.version_id,
            kernel=kernel_release(),
            arch=machine_arch(),
            ram_mb=ram,
            is_root=self.is_root(),
        )

    async def run(
        self,
        cmd: list[str],
        *,
        timeout: float | None = None,
        needs_root: bool = False,
        env: dict[str, str] | None = None,
        on_line: LineCallback | None = None,
        cwd: str | None = None,
    ) -> CommandResult:
        del needs_root  # enforced by the engine before calling run()
        if not cmd or not isinstance(cmd, list) or any(not isinstance(c, str) for c in cmd):
            raise ValueError("cmd must be a non-empty list[str] (no shell strings)")

        argv = self.wrap(cmd)
        return await _run_argv(argv, timeout=timeout, env=env, on_line=on_line, cwd=cwd)


async def _run_argv(
    argv: list[str],
    *,
    timeout: float | None,
    env: dict[str, str] | None,
    on_line: LineCallback | None,
    cwd: str | None,
) -> CommandResult:
    started = time.monotonic()
    proc = await asyncio.create_subprocess_exec(
        *argv,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=merge_env(env),
        cwd=cwd,
    )

    stdout_chunks: list[str] = []
    stderr_chunks: list[str] = []
    timed_out = False

    async def _pump(stream: asyncio.StreamReader, name: str, sink: list[str]) -> None:
        while True:
            raw = await stream.readline()
            if not raw:
                break
            line = raw.decode("utf-8", errors="replace")
            if line.endswith("\n"):
                line = line[:-1]
            sink.append(line)
            if on_line is not None:
                result = on_line(name, line)
                if asyncio.iscoroutine(result):
                    await result

    assert proc.stdout is not None
    assert proc.stderr is not None
    waiter = asyncio.gather(
        _pump(proc.stdout, "stdout", stdout_chunks),
        _pump(proc.stderr, "stderr", stderr_chunks),
        proc.wait(),
    )

    try:
        if timeout is not None:
            await asyncio.wait_for(waiter, timeout=timeout)
        else:
            await waiter
    except TimeoutError:
        timed_out = True
        proc.kill()
        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(proc.wait(), timeout=5.0)
        waiter.cancel()
        with contextlib.suppress(asyncio.CancelledError, Exception):
            await waiter

    duration = time.monotonic() - started
    exit_code = proc.returncode
    if exit_code is None:
        exit_code = -9 if timed_out else -1
    return CommandResult(
        exit_code=exit_code,
        stdout="\n".join(stdout_chunks),
        stderr="\n".join(stderr_chunks),
        timed_out=timed_out,
        duration_seconds=duration,
        argv=argv,
    )
