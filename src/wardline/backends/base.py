"""Backend interface — plugins talk only to a Backend, never subprocess."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

from wardline.core.models import BackendKind, HostInfo

LineCallback = Callable[[str, str], Awaitable[None] | None]


@dataclass(slots=True)
class CommandResult:
    """Outcome of a single backend.run() invocation."""

    exit_code: int
    stdout: str
    stderr: str
    timed_out: bool = False
    duration_seconds: float = 0.0
    argv: list[str] = field(default_factory=list)


class BackendError(Exception):
    """Raised for backend-level failures (not non-zero exit codes)."""


class Backend(ABC):
    """Execution backend (local / docker / ssh)."""

    kind: BackendKind

    @abstractmethod
    def prefix(self) -> list[str]:
        """Low-priority wrapper argv, e.g. ``nice -n 19 ionice -c3``."""

    @abstractmethod
    def path(self, host_path: str) -> str:
        """Translate a host path into the path tools should see."""

    @abstractmethod
    def is_root(self) -> bool:
        """Whether commands run with effective root on the target."""

    @abstractmethod
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
        """Run an argv list (never a shell string). Stream lines via on_line."""

    @abstractmethod
    async def read_file(self, path: str) -> bytes:
        """Read a file from the target. Raises FileNotFoundError if missing."""

    @abstractmethod
    async def exists(self, path: str) -> bool:
        """Return True if path exists on the target."""

    @abstractmethod
    async def which(self, binary: str) -> str | None:
        """Return absolute path of binary on the target, or None."""

    @abstractmethod
    async def host_info(self) -> HostInfo:
        """Gather hostname, distro, RAM, root status, etc."""

    async def total_ram_mb(self) -> int | None:
        """Optional helper; default reads nothing. Local overrides."""
        return None

    def wrap(self, cmd: list[str]) -> list[str]:
        """Prepend low-priority prefix to an argv list."""
        if not cmd:
            raise ValueError("command must be a non-empty argument list")
        prefix = self.prefix()
        if not prefix:
            return list(cmd)
        return [*prefix, *cmd]


def merge_env(extra: dict[str, str] | None) -> dict[str, str]:
    """Build an env mapping for subprocess (starts from current environ)."""
    import os

    env = dict(os.environ)
    if extra:
        env.update(extra)
    return env


def as_str_map(data: dict[str, Any]) -> dict[str, str]:
    return {str(k): str(v) for k, v in data.items()}
