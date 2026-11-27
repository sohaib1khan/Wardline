"""SSH backend — agentless remote execution via asyncssh (key auth only)."""

from __future__ import annotations

import asyncio
import shlex
import time
from pathlib import Path

import asyncssh

from wardline.backends.base import Backend, BackendError, CommandResult, LineCallback
from wardline.core.distro import DistroInfo, PackageManager, detect_distro
from wardline.core.hosts import HostRecord, ensure_known_hosts_file, known_hosts_path
from wardline.core.models import BackendKind, HostInfo

NICE_ARGV = ["nice", "-n", "19"]
IONICE_ARGV = ["ionice", "-c", "3"]


class SSHHostKeyError(BackendError):
    """Host key verification failed (unknown or mismatched)."""

    def __init__(
        self,
        message: str,
        *,
        host: str,
        fingerprint: str = "",
        unknown: bool = False,
        mismatched: bool = False,
    ) -> None:
        super().__init__(message)
        self.host = host
        self.fingerprint = fingerprint
        self.unknown = unknown
        self.mismatched = mismatched


class SSHBackend(Backend):
    """Run scanner tools on a remote host over SSH (key auth, strict known_hosts)."""

    kind = BackendKind.SSH

    def __init__(
        self,
        record: HostRecord,
        *,
        known_hosts: Path | None = None,
        connect_timeout: float = 30.0,
        apply_priority: bool = True,
    ) -> None:
        self.record = record
        self.known_hosts = ensure_known_hosts_file(known_hosts or known_hosts_path())
        self.connect_timeout = connect_timeout
        self._apply_priority = apply_priority
        self._conn: asyncssh.SSHClientConnection | None = None
        self._is_root: bool | None = None

    def path(self, host_path: str) -> str:
        return host_path

    def prefix(self) -> list[str]:
        if not self._apply_priority:
            return []
        return [*NICE_ARGV, *IONICE_ARGV]

    def is_root(self) -> bool:
        if self._is_root is not None:
            return self._is_root
        # Conservative default until probed; engine may skip needs_root plugins.
        return bool(self.record.use_sudo) or self.record.user == "root"

    async def connect(self) -> asyncssh.SSHClientConnection:
        if self._conn is not None:
            return self._conn

        client_keys: list[str] = []
        identity = self.record.resolve_identity()
        if identity is not None:
            if not identity.is_file():
                raise BackendError(f"identity file not found: {identity}")
            client_keys.append(str(identity))

        connect_kwargs: dict = {
            "port": self.record.port,
            "username": self.record.user,
            "known_hosts": str(self.known_hosts),
            # Never use password / keyboard-interactive (key auth only).
            "password": None,
            "preferred_auth": ["publickey"],
            "login_timeout": self.connect_timeout,
        }
        if client_keys:
            connect_kwargs["client_keys"] = client_keys
        try:
            self._conn = await asyncio.wait_for(
                asyncssh.connect(self.record.host, **connect_kwargs),
                timeout=self.connect_timeout + 5,
            )
        except asyncssh.HostKeyNotVerifiable as exc:
            fingerprint = await _probe_fingerprint(self.record.host, self.record.port)
            # Distinguish unknown vs wrong key by checking if host is listed.
            listed = _host_listed(self.known_hosts, self.record.host)
            raise SSHHostKeyError(
                (
                    f"host key {'mismatch' if listed else 'unknown'} for "
                    f"{self.record.host}: {exc}. "
                    + (
                        "Refusing to connect (strict known_hosts)."
                        if listed
                        else "Confirm the fingerprint, then: wardline hosts accept-key "
                        f"{self.record.name}"
                    )
                ),
                host=self.record.host,
                fingerprint=fingerprint,
                unknown=not listed,
                mismatched=listed,
            ) from exc
        except (OSError, asyncssh.Error, TimeoutError) as exc:
            raise BackendError(
                f"SSH connect failed for {self.record.name} ({self.record.host}): {exc}"
            ) from exc

        # Probe effective root.
        result = await self.run(["id", "-u"], timeout=15.0)
        self._is_root = result.exit_code == 0 and result.stdout.strip() == "0"
        if not self._is_root and self.record.use_sudo:
            # sudo -n id -u
            sudo_id = await self._run_remote(["sudo", "-n", "id", "-u"], timeout=15.0)
            self._is_root = sudo_id.exit_code == 0 and sudo_id.stdout.strip() == "0"
        return self._conn

    async def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            await self._conn.wait_closed()
            self._conn = None

    async def which(self, binary: str) -> str | None:
        if not binary or any(c in binary for c in " \t\n/;|&$"):
            return None
        result = await self.run(["sh", "-c", f"command -v {shlex.quote(binary)}"], timeout=15.0)
        if result.exit_code == 0 and result.stdout.strip():
            return result.stdout.strip().splitlines()[0].strip()
        return None

    async def exists(self, path: str) -> bool:
        result = await self.run(["test", "-e", path], timeout=15.0)
        return result.exit_code == 0

    async def read_file(self, path: str) -> bytes:
        result = await self.run(["cat", path], timeout=60.0)
        if result.exit_code != 0:
            raise FileNotFoundError(path)
        return result.stdout.encode("utf-8", errors="replace")

    async def total_ram_mb(self) -> int | None:
        result = await self.run(["sh", "-c", "awk '/MemTotal/ {print $2}' /proc/meminfo"], timeout=15.0)
        if result.exit_code != 0:
            return None
        try:
            kib = int(result.stdout.strip().splitlines()[0])
            return kib // 1024
        except (ValueError, IndexError):
            return None

    async def host_info(self) -> HostInfo:
        await self.connect()
        distro = await self._remote_distro()
        hostname = self.record.display_name()
        hn = await self.run(["hostname", "-f"], timeout=10.0)
        if hn.exit_code == 0 and hn.stdout.strip():
            hostname = hn.stdout.strip()
        elif self.record.alias:
            hostname = self.record.alias
        kernel = ""
        uname = await self.run(["uname", "-r"], timeout=10.0)
        if uname.exit_code == 0:
            kernel = uname.stdout.strip()
        arch = ""
        machine = await self.run(["uname", "-m"], timeout=10.0)
        if machine.exit_code == 0:
            arch = machine.stdout.strip()
        return HostInfo(
            hostname=hostname,
            distro=distro.id,
            version=distro.version_id,
            kernel=kernel,
            arch=arch,
            ram_mb=await self.total_ram_mb(),
            is_root=self.is_root(),
        )

    async def _remote_distro(self) -> DistroInfo:
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
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "os-release"
            path.write_text(raw.decode("utf-8", errors="replace"), encoding="utf-8")
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
        if not cmd or not isinstance(cmd, list) or any(not isinstance(c, str) for c in cmd):
            raise ValueError("cmd must be a non-empty list[str] (no shell strings)")
        await self.connect()

        argv = list(cmd)
        if needs_root and self.record.user != "root" and self.record.use_sudo:
            argv = ["sudo", "-n", *argv]
        if self.prefix():
            argv = [*self.prefix(), *argv]
        return await self._run_remote(argv, timeout=timeout, env=env, on_line=on_line, cwd=cwd)

    async def _run_remote(
        self,
        argv: list[str],
        *,
        timeout: float | None,
        env: dict[str, str] | None = None,
        on_line: LineCallback | None = None,
        cwd: str | None = None,
    ) -> CommandResult:
        assert self._conn is not None
        started = time.monotonic()
        # Build a single remote argv string safely.
        remote_cmd = " ".join(shlex.quote(a) for a in argv)
        if cwd:
            remote_cmd = f"cd {shlex.quote(cwd)} && {remote_cmd}"
        if env:
            exports = " ".join(f"{k}={shlex.quote(v)}" for k, v in env.items())
            remote_cmd = f"env {exports} {remote_cmd}"

        timed_out = False
        stdout = ""
        stderr = ""
        exit_code = -1
        try:
            result = await asyncio.wait_for(
                self._conn.run(remote_cmd, check=False, encoding="utf-8"),
                timeout=timeout,
            )
            stdout = _as_str(result.stdout)
            stderr = _as_str(result.stderr)
            exit_code = int(result.exit_status if result.exit_status is not None else -1)
            if on_line is not None:
                for line in stdout.splitlines():
                    maybe = on_line("stdout", line)
                    if asyncio.iscoroutine(maybe):
                        await maybe
                for line in stderr.splitlines():
                    maybe = on_line("stderr", line)
                    if asyncio.iscoroutine(maybe):
                        await maybe
        except TimeoutError:
            timed_out = True
            exit_code = -9

        return CommandResult(
            exit_code=exit_code,
            stdout=stdout.rstrip("\n"),
            stderr=stderr.rstrip("\n"),
            timed_out=timed_out,
            duration_seconds=time.monotonic() - started,
            argv=argv,
        )


def _as_str(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


async def fetch_host_key_fingerprint(host: str, port: int = 22) -> tuple[str, str]:
    """Return (fingerprint, known_hosts_line) for an unverified server key."""
    key = await asyncssh.get_server_host_key(host, port=port)
    if key is None:
        raise BackendError(f"server presented no host key: {host}")
    fingerprint = key.get_fingerprint()
    line = f"{host} {key.export_public_key().decode().strip()}\n"
    return fingerprint, line


async def accept_host_key(
    host: str,
    *,
    port: int = 22,
    known_hosts: Path | None = None,
) -> str:
    """Fetch the current server host key and append it to known_hosts.

    Never called automatically — requires explicit CLI/TUI confirmation.
    """
    path = ensure_known_hosts_file(known_hosts)
    fingerprint, line = await fetch_host_key_fingerprint(host, port=port)
    existing = path.read_text(encoding="utf-8")
    # Replace any previous lines for this host (wrong-key recovery after confirm).
    kept = [ln for ln in existing.splitlines() if ln.strip() and not ln.startswith(f"{host} ")]
    kept.append(line.rstrip("\n"))
    from wardline.core.paths import write_private_file

    write_private_file(path, "\n".join(kept) + "\n")
    return fingerprint


def _host_listed(known_hosts: Path, host: str) -> bool:
    if not known_hosts.is_file():
        return False
    prefix = f"{host} "
    return any(
        line.startswith(prefix) for line in known_hosts.read_text(encoding="utf-8").splitlines()
    )


async def _probe_fingerprint(host: str, port: int) -> str:
    try:
        fp, _ = await fetch_host_key_fingerprint(host, port=port)
        return fp
    except Exception:
        return ""
