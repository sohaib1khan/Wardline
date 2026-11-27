"""Plugin interface and auto-discovery registry."""

from __future__ import annotations

import importlib
import pkgutil
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from wardline.backends.base import Backend, CommandResult
from wardline.core.distro import DistroInfo
from wardline.core.models import (
    BackendKind,
    Category,
    Finding,
    PluginStatus,
)


class CapabilityLevel(StrEnum):
    FULL = "full"
    PARTIAL = "partial"
    UNAVAILABLE = "unavailable"


@dataclass(frozen=True, slots=True)
class Capability:
    level: CapabilityLevel
    note: str = ""


@dataclass(slots=True)
class DetectResult:
    installed: bool
    version: str | None = None
    path: str | None = None
    denylisted: bool = False
    denylist_reason: str | None = None
    detail: str = ""


@dataclass(slots=True)
class ParseResult:
    findings: list[Finding] = field(default_factory=list)
    extras: dict[str, Any] = field(default_factory=dict)


def default_capabilities(
    *,
    local: CapabilityLevel = CapabilityLevel.FULL,
    docker: CapabilityLevel = CapabilityLevel.FULL,
    ssh: CapabilityLevel = CapabilityLevel.FULL,
    notes: dict[BackendKind, str] | None = None,
) -> dict[BackendKind, Capability]:
    notes = notes or {}
    return {
        BackendKind.LOCAL: Capability(local, notes.get(BackendKind.LOCAL, "")),
        BackendKind.DOCKER: Capability(docker, notes.get(BackendKind.DOCKER, "")),
        BackendKind.SSH: Capability(ssh, notes.get(BackendKind.SSH, "")),
    }


class Plugin(ABC):
    """One scanner tool wrapped as a Wardline plugin."""

    name: str
    display_name: str
    category: Category
    description: str
    needs_root: bool = False
    min_ram_mb: int = 0
    needs_network: bool = False
    default_timeout: float = 300.0
    capabilities: dict[BackendKind, Capability] = default_capabilities()
    supported_distros: frozenset[str] | None = None  # None = all
    version_denylist: frozenset[str] = frozenset()
    hidden: bool = False  # hide from doctor / launcher when True

    @abstractmethod
    async def detect(self, backend: Backend) -> DetectResult:
        """Return whether the tool is installed (and version / denylist)."""

    @abstractmethod
    def install_hint(self, distro: DistroInfo) -> list[str]:
        """Exact install commands to show the user (never auto-run here)."""

    @abstractmethod
    def build_commands(
        self, backend: Backend, options: dict[str, Any] | None = None
    ) -> list[list[str]]:
        """Return one or more argv lists to run via the backend."""

    @abstractmethod
    def parse(
        self,
        raw_output: str,
        exit_code: int,
        *,
        scan_id: str,
        host: str,
        options: dict[str, Any] | None = None,
    ) -> ParseResult:
        """Turn raw tool output into Findings (+ optional extras)."""

    def interpret_exit_code(self, code: int) -> PluginStatus:
        """Map a process exit code to PluginStatus. Override per tool."""
        if code == 0:
            return PluginStatus.OK
        return PluginStatus.FAILED

    async def collect_raw_output(self, backend: Backend, results: list[CommandResult]) -> str:
        """Combine command outputs. Plugins may override (e.g. Lynis report file)."""
        del backend
        parts: list[str] = []
        for result in results:
            if result.stdout:
                parts.append(result.stdout)
            if result.stderr:
                parts.append(result.stderr)
        return "\n".join(parts).strip()

    def denylist_findings(self, *, scan_id: str, host: str, version: str | None) -> list[Finding]:
        """Optional critical findings when a denylisted tool version is detected."""
        del scan_id, host, version
        return []

    def supports_distro(self, distro: DistroInfo) -> bool:
        if self.supported_distros is None:
            return True
        return distro.id in self.supported_distros or distro.family in self.supported_distros

    def check_denylist(self, version: str | None) -> str | None:
        """Return a reason string if version is denylisted, else None."""
        if version and version in self.version_denylist:
            return f"version {version} is denylisted"
        return None


class PluginRegistry:
    """In-memory registry of plugin instances, keyed by ``name``."""

    def __init__(self) -> None:
        self._plugins: dict[str, Plugin] = {}

    def register(self, plugin: Plugin) -> None:
        if plugin.name in self._plugins:
            raise ValueError(f"duplicate plugin name: {plugin.name}")
        self._plugins[plugin.name] = plugin

    def get(self, name: str) -> Plugin:
        try:
            return self._plugins[name]
        except KeyError as exc:
            raise KeyError(f"unknown plugin: {name}") from exc

    def list(self, *, include_hidden: bool = False) -> list[Plugin]:
        plugins = list(self._plugins.values())
        if not include_hidden:
            plugins = [p for p in plugins if not p.hidden]
        return sorted(plugins, key=lambda p: p.name)

    def names(self, *, include_hidden: bool = False) -> list[str]:
        return [p.name for p in self.list(include_hidden=include_hidden)]

    def __len__(self) -> int:
        return len(self._plugins)

    def __contains__(self, name: str) -> bool:
        return name in self._plugins


_REGISTRY: PluginRegistry | None = None


def get_registry(*, refresh: bool = False) -> PluginRegistry:
    """Return the process-wide registry, discovering plugins on first use."""
    global _REGISTRY
    if _REGISTRY is None or refresh:
        _REGISTRY = PluginRegistry()
        discover_plugins(_REGISTRY)
    return _REGISTRY


def discover_plugins(registry: PluginRegistry, package_name: str = "wardline.plugins") -> None:
    """Import all modules under ``wardline.plugins`` and register Plugin subclasses."""
    package = importlib.import_module(package_name)
    for mod_info in pkgutil.iter_modules(package.__path__, package.__name__ + "."):
        if mod_info.name.endswith(".base"):
            continue
        module = importlib.import_module(mod_info.name)
        for obj in vars(module).values():
            if not (
                isinstance(obj, type)
                and issubclass(obj, Plugin)
                and obj is not Plugin
                and getattr(obj, "name", None)
            ):
                continue
            abstracts = getattr(obj, "__abstractmethods__", None)
            if abstracts:
                continue
            try:
                instance = obj()
            except TypeError:
                continue
            if instance.name not in registry:
                registry.register(instance)
