"""SSH backend safety: unknown key prompts path, wrong key fails, accept-key saves."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import asyncssh
import pytest

from wardline.backends.ssh import (
    SSHBackend,
    SSHHostKeyError,
    accept_host_key,
    fetch_host_key_fingerprint,
)
from wardline.core.hosts import HostRecord


def _record() -> HostRecord:
    return HostRecord(name="lab01", host="192.0.2.10", user="wardline", use_sudo=False)


@pytest.mark.asyncio
async def test_unknown_host_key_raises_with_fingerprint(tmp_path: Path) -> None:
    known = tmp_path / "known_hosts"
    known.write_text("", encoding="utf-8")
    backend = SSHBackend(_record(), known_hosts=known, apply_priority=False)

    key = asyncssh.generate_private_key("ssh-ed25519").convert_to_public()

    with (
        patch(
            "wardline.backends.ssh.asyncssh.connect",
            new=AsyncMock(side_effect=asyncssh.HostKeyNotVerifiable("unknown")),
        ),
        patch(
            "wardline.backends.ssh.asyncssh.get_server_host_key",
            new=AsyncMock(return_value=key),
        ),pytest.raises(SSHHostKeyError) as excinfo
    ):
        await backend.connect()
    err = excinfo.value
    assert err.unknown is True
    assert err.mismatched is False
    assert err.fingerprint.startswith("SHA256:")
    assert "accept-key" in str(err)


@pytest.mark.asyncio
async def test_wrong_host_key_fails_as_mismatch(tmp_path: Path) -> None:
    known = tmp_path / "known_hosts"
    # Pretend we already trust a different key for this host.
    known.write_text("192.0.2.10 ssh-ed25519 AAAAfakekey\n", encoding="utf-8")
    backend = SSHBackend(_record(), known_hosts=known, apply_priority=False)
    key = asyncssh.generate_private_key("ssh-ed25519").convert_to_public()

    with (
        patch(
            "wardline.backends.ssh.asyncssh.connect",
            new=AsyncMock(side_effect=asyncssh.HostKeyNotVerifiable("mismatch")),
        ),
        patch(
            "wardline.backends.ssh.asyncssh.get_server_host_key",
            new=AsyncMock(return_value=key),
        ),pytest.raises(SSHHostKeyError) as excinfo
    ):
        await backend.connect()
    assert excinfo.value.mismatched is True
    assert excinfo.value.unknown is False
    assert "mismatch" in str(excinfo.value).lower()


@pytest.mark.asyncio
async def test_accept_host_key_writes_known_hosts(tmp_path: Path) -> None:
    known = tmp_path / "known_hosts"
    key = asyncssh.generate_private_key("ssh-ed25519").convert_to_public()
    with patch(
        "wardline.backends.ssh.asyncssh.get_server_host_key",
        new=AsyncMock(return_value=key),
    ):
        fp = await accept_host_key("192.0.2.10", port=22, known_hosts=known)
    text = known.read_text(encoding="utf-8")
    assert "192.0.2.10" in text
    assert key.export_public_key().decode().strip().split()[0] in text
    assert fp == key.get_fingerprint()


@pytest.mark.asyncio
async def test_accept_replaces_previous_line(tmp_path: Path) -> None:
    known = tmp_path / "known_hosts"
    known.write_text("192.0.2.10 ssh-ed25519 OLDKEY\n", encoding="utf-8")
    key = asyncssh.generate_private_key("ssh-ed25519").convert_to_public()
    with patch(
        "wardline.backends.ssh.asyncssh.get_server_host_key",
        new=AsyncMock(return_value=key),
    ):
        await accept_host_key("192.0.2.10", known_hosts=known)
    lines = [ln for ln in known.read_text(encoding="utf-8").splitlines() if ln.startswith("192.0.2.10 ")]
    assert len(lines) == 1
    assert "OLDKEY" not in lines[0]


@pytest.mark.asyncio
async def test_ssh_run_builds_remote_command(tmp_path: Path) -> None:
    known = tmp_path / "known_hosts"
    known.write_text("", encoding="utf-8")
    backend = SSHBackend(_record(), known_hosts=known, apply_priority=False)

    mock_conn = MagicMock()
    mock_result = MagicMock()
    mock_result.stdout = "0\n"
    mock_result.stderr = ""
    mock_result.exit_status = 0
    mock_conn.run = AsyncMock(return_value=mock_result)
    mock_conn.close = MagicMock()
    mock_conn.wait_closed = AsyncMock()

    with patch(
        "wardline.backends.ssh.asyncssh.connect",
        new=AsyncMock(return_value=mock_conn),
    ):
        # connect probes id -u
        await backend.connect()
        result = await backend.run(["ss", "-tulpn"], timeout=5.0)
    assert result.exit_code == 0
    # Last run should include ss
    assert any("ss" in (c.args[0] if c.args else "") for c in mock_conn.run.await_args_list) or any(
        "ss" in str(call) for call in mock_conn.run.await_args_list
    )


@pytest.mark.asyncio
async def test_fetch_fingerprint(tmp_path: Path) -> None:
    del tmp_path
    key = asyncssh.generate_private_key("ssh-ed25519").convert_to_public()
    with patch(
        "wardline.backends.ssh.asyncssh.get_server_host_key",
        new=AsyncMock(return_value=key),
    ):
        fp, line = await fetch_host_key_fingerprint("192.0.2.10")
    assert fp.startswith("SHA256:")
    assert line.startswith("192.0.2.10 ")
