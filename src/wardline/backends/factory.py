"""Construct execution backends by name."""

from __future__ import annotations

from wardline.backends.base import Backend, BackendError
from wardline.backends.docker import DockerBackend
from wardline.backends.local import LocalBackend
from wardline.backends.ssh import SSHBackend
from wardline.core.hosts import HostRecord, load_hosts


def get_backend(
    name: str,
    *,
    host: str | None = None,
    host_record: HostRecord | None = None,
) -> Backend:
    key = name.strip().lower()
    if key == "local":
        return LocalBackend()
    if key == "docker":
        return DockerBackend()
    if key == "ssh":
        record = host_record
        if record is None:
            if not host:
                raise BackendError(
                    "SSH backend requires --host NAME (or use --all-hosts for fleet)"
                )
            inventory = load_hosts()
            try:
                record = inventory.get(host)
            except KeyError as exc:
                raise BackendError(str(exc)) from exc
        return SSHBackend(record)
    raise BackendError(f"unknown backend {name!r}; use local, docker, or ssh")
