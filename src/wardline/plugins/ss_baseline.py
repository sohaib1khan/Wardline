"""ss baseline — unexplained and exposed listeners."""

from __future__ import annotations

import re
from typing import Any

from wardline.backends.base import Backend
from wardline.core.distro import DistroInfo
from wardline.core.models import Category, Finding, PluginStatus, Severity
from wardline.plugins.base import DetectResult, ParseResult, Plugin, default_capabilities

DB_PORTS = frozenset({3306, 5432, 6379, 27017})
EXPOSED_ADDRS = frozenset({"0.0.0.0", "*", "::", "[::]"})

# ss -tulpn line (header skipped). Local Address:Port is the 5th field.
_LINE_RE = re.compile(
    r"^(?P<netid>tcp|udp|tcp6|udp6)\s+"
    r"(?P<state>\S+)\s+"
    r"\d+\s+\d+\s+"
    r"(?P<local>\S+)\s+"
    r"(?P<peer>\S+)"
    r"(?:\s+(?P<process>.*))?$"
)


def _split_host_port(local: str) -> tuple[str, int | None]:
    if local.startswith("["):
        # [::]:22 or [fe80::1]:80
        if "]:" in local:
            host, _, port_s = local.rpartition("]:")
            host = host + "]"
            try:
                return host, int(port_s)
            except ValueError:
                return local, None
        return local, None
    if ":" not in local:
        return local, None
    host, _, port_s = local.rpartition(":")
    try:
        return host, int(port_s)
    except ValueError:
        return local, None


def _proto(netid: str) -> str:
    return "udp" if netid.startswith("udp") else "tcp"


def _is_exposed(host: str) -> bool:
    return host in EXPOSED_ADDRS


class SsBaselinePlugin(Plugin):
    name = "ss_baseline"
    display_name = "ss baseline"
    category = Category.NETWORK
    description = "List listening sockets and flag unexplained or exposed DB listeners."
    needs_root = False
    default_timeout = 30.0
    capabilities = default_capabilities()

    async def detect(self, backend: Backend) -> DetectResult:
        path = await backend.which("ss")
        version = None
        if path:
            result = await backend.run(["ss", "-V"], timeout=10.0)
            # ss prints version to stderr or stdout depending on build.
            text = f"{result.stdout}\n{result.stderr}"
            match = re.search(r"ss utility,\s*(\S+)", text)
            if match:
                version = match.group(1)
            elif result.exit_code == 0:
                version = "unknown"
        return DetectResult(installed=path is not None, version=version, path=path)

    def install_hint(self, distro: DistroInfo) -> list[str]:
        if distro.is_debian_family:
            return ["sudo apt update && sudo apt install -y iproute2"]
        if distro.is_rhel_family:
            return ["sudo dnf install -y iproute"]
        return ["# install iproute2 / iproute for the `ss` binary"]

    def build_commands(
        self, backend: Backend, options: dict[str, Any] | None = None
    ) -> list[list[str]]:
        del backend, options
        return [["ss", "-tulpn"]]

    def interpret_exit_code(self, code: int) -> PluginStatus:
        return PluginStatus.OK if code == 0 else PluginStatus.FAILED

    def parse(
        self,
        raw_output: str,
        exit_code: int,
        *,
        scan_id: str,
        host: str,
        options: dict[str, Any] | None = None,
    ) -> ParseResult:
        del exit_code
        options = options or {}
        expected = {
            str(item).lower()
            for item in options.get("expected_listeners", ["22/tcp", "80/tcp", "443/tcp"])
        }

        findings: list[Finding] = []
        listeners: list[dict[str, Any]] = []

        for line in raw_output.splitlines():
            line = line.strip()
            if not line or line.lower().startswith("netid"):
                continue
            match = _LINE_RE.match(line)
            if not match:
                continue
            netid = match.group("netid")
            state = match.group("state")
            if netid.startswith("tcp") and state != "LISTEN":
                continue
            if netid.startswith("udp") and state not in {"UNCONN", "LISTEN"}:
                continue

            local = match.group("local")
            process = (match.group("process") or "").strip()
            addr, port = _split_host_port(local)
            if port is None:
                continue
            proto = _proto(netid)
            key = f"{port}/{proto}"
            listeners.append(
                {
                    "key": key,
                    "local": local,
                    "addr": addr,
                    "port": port,
                    "proto": proto,
                    "process": process,
                }
            )

            if key.lower() not in expected:
                severity = Severity.MEDIUM
                title = f"Unexplained listener {key} on {local}"
                if port in DB_PORTS and _is_exposed(addr):
                    severity = Severity.HIGH
                    title = f"Exposed database port {key} on {local}"
                findings.append(
                    Finding(
                        scan_id=scan_id,
                        host=host,
                        plugin=self.name,
                        rule_id=f"SS-LISTEN-{port}-{proto}",
                        category=Category.NETWORK,
                        severity=severity,
                        title=title,
                        description=(
                            f"Listening socket {local} ({process or 'unknown process'}) "
                            f"is not in scan.ss.expected_listeners."
                        ),
                        location=f"{local} ({key})",
                        evidence=line[:500],
                        fix_hint=(
                            "Confirm the service is required; bind it to localhost if possible; "
                            "or add it to scan.ss.expected_listeners if intentional."
                        ),
                    )
                )

        return ParseResult(
            findings=findings,
            extras={"listener_count": len(listeners), "listeners": listeners},
        )
