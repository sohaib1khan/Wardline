"""Docker backend — tools run in the wardline-scanner container via docker exec."""

from __future__ import annotations

import asyncio
import platform
import shutil
import tempfile
from pathlib import Path

from wardline.backends.base import Backend, BackendError, CommandResult, LineCallback
from wardline.backends.local import _run_argv, read_total_ram_mb
from wardline.core.distro import DistroInfo, PackageManager, detect_distro
from wardline.core.models import BackendKind, HostInfo

DEFAULT_CONTAINER = "wardline-scanner"
DEFAULT_IMAGE = "wardline-scanner:local"
HOST_ROOT = "/host"
NICE_ARGV = ["nice", "-n", "19"]
IONICE_ARGV = ["ionice", "-c", "3"]


class DockerBackend(Backend):
    """Execute scanner tools inside a long-lived container; Vault stays on the host."""

    kind = BackendKind.DOCKER

    def __init__(
        self,
        *,
        container: str = DEFAULT_CONTAINER,
        image: str = DEFAULT_IMAGE,
        docker_bin: str = "docker",
        apply_priority: bool = True,
    ) -> None:
        self.container = container
        self.image = image
        self.docker_bin = docker_bin
        self._apply_priority = apply_priority
        self._prefix_cache: list[str] | None = None

    def is_root(self) -> bool:
        # Scanner container runs as root so plugins that need_root can execute.
        return True

    def path(self, host_path: str) -> str:
        """Map a host path into the container's read-only ``/host`` mount."""
        raw = host_path.strip() or "/"
        if not raw.startswith("/"):
            raw = "/" + raw
        if raw == "/":
            return HOST_ROOT
        if raw == HOST_ROOT or raw.startswith(HOST_ROOT + "/"):
            return raw
        return f"{HOST_ROOT}{raw}"

    def prefix(self) -> list[str]:
        if not self._apply_priority:
            return []
        if self._prefix_cache is not None:
            return list(self._prefix_cache)
        self._prefix_cache = [*NICE_ARGV, *IONICE_ARGV]
        return list(self._prefix_cache)

    def _docker_available(self) -> bool:
        return shutil.which(self.docker_bin) is not None

    async def ensure_ready(self) -> None:
        if not self._docker_available():
            raise BackendError(
                f"{self.docker_bin!r} not found on PATH — install Docker to use this backend"
            )
        result = await _run_argv(
            [self.docker_bin, "inspect", "-f", "{{.State.Running}}", self.container],
            timeout=15.0,
            env=None,
            on_line=None,
            cwd=None,
        )
        if result.exit_code != 0 or result.stdout.strip().lower() != "true":
            raise BackendError(
                f"container {self.container!r} is not running. "
                "Start it with: wardline docker up"
            )

    async def which(self, binary: str) -> str | None:
        await self.ensure_ready()
        # Avoid shell injection: only allow simple binary names.
        if not binary or any(c in binary for c in " \t\n/;|&$"):
            return None
        result = await self.run(["sh", "-c", f"command -v {binary}"], timeout=15.0)
        lines = result.stdout.strip().splitlines()
        if result.exit_code == 0 and lines:
            return lines[0].strip()
        return None

    async def exists(self, path: str) -> bool:
        mapped = self.path(path) if not path.startswith(HOST_ROOT) else path
        result = await self.run(["test", "-e", mapped], timeout=15.0)
        return result.exit_code == 0

    async def read_file(self, path: str) -> bytes:
        mapped = self.path(path) if not str(path).startswith(HOST_ROOT) else path
        result = await self.run(["cat", mapped], timeout=60.0)
        if result.exit_code != 0:
            raise FileNotFoundError(path)
        return result.stdout.encode("utf-8", errors="replace")

    async def total_ram_mb(self) -> int | None:
        return await asyncio.to_thread(read_total_ram_mb)

    async def host_info(self) -> HostInfo:
        await self.ensure_ready()
        distro = await self._host_distro()
        hostname = platform.node() or "localhost"
        try:
            hn = (await self.read_file("/etc/hostname")).decode().strip()
            if hn:
                hostname = hn
        except (FileNotFoundError, OSError, BackendError):
            pass
        kernel = platform.release()
        try:
            k = await self.run(["uname", "-r"], timeout=10.0)
            if k.exit_code == 0 and k.stdout.strip():
                kernel = k.stdout.strip()
        except BackendError:
            pass
        return HostInfo(
            hostname=hostname,
            distro=distro.id,
            version=distro.version_id,
            kernel=kernel,
            arch=platform.machine() or "",
            ram_mb=await self.total_ram_mb(),
            is_root=self.is_root(),
        )

    async def _host_distro(self) -> DistroInfo:
        try:
            raw = await self.read_file("/etc/os-release")
        except (FileNotFoundError, OSError, BackendError):
            return DistroInfo(
                id="unknown",
                name="unknown",
                version_id="",
                version_codename="",
                pretty_name="unknown",
                id_like=(),
                package_manager=PackageManager.UNKNOWN,
                family="unknown",
            )
        text = raw.decode("utf-8", errors="replace")
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "os-release"
            path.write_text(text, encoding="utf-8")
            return detect_distro(path)

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
        del needs_root
        if not cmd or not isinstance(cmd, list) or any(not isinstance(c, str) for c in cmd):
            raise ValueError("cmd must be a non-empty list[str] (no shell strings)")
        await self.ensure_ready()

        inner = [*self.prefix(), *cmd]
        argv = [self.docker_bin, "exec"]
        if cwd:
            argv.extend(["-w", cwd])
        if env:
            for key, value in env.items():
                argv.extend(["-e", f"{key}={value}"])
        argv.append(self.container)
        argv.extend(inner)
        return await _run_argv(argv, timeout=timeout, env=None, on_line=on_line, cwd=None)
