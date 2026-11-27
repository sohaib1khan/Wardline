"""Execution backends: local, Docker, SSH."""

from wardline.backends.base import Backend, CommandResult
from wardline.backends.docker import DockerBackend
from wardline.backends.factory import get_backend
from wardline.backends.local import LocalBackend
from wardline.backends.ssh import SSHBackend, SSHHostKeyError

__all__ = [
    "Backend",
    "CommandResult",
    "DockerBackend",
    "LocalBackend",
    "SSHBackend",
    "SSHHostKeyError",
    "get_backend",
]
