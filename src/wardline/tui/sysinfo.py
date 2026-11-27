"""Local host + security posture snippets for the dashboard (no scan required)."""

from __future__ import annotations

import os
import platform
from dataclasses import dataclass, field
from pathlib import Path

from wardline.backends.local import read_total_ram_mb
from wardline.core.distro import detect_distro, kernel_release, machine_arch
from wardline.core.ssh_inspect import gather_ssh_inspection


@dataclass
class SecuritySnapshot:
    hostname: str = ""
    distro: str = ""
    version: str = ""
    kernel: str = ""
    arch: str = ""
    ram_mb: int | None = None
    is_root: bool = False
    uptime: str = "—"
    loadavg: str = "—"
    mac: str = "—"  # AppArmor / SELinux
    firewall: str = "—"
    aslr: str = "—"
    sshd: str = "—"
    auto_updates: str = "—"
    listening_hint: str = "—"
    lines_sys: list[str] = field(default_factory=list)
    lines_security: list[str] = field(default_factory=list)
    lines_ssh: list[str] = field(default_factory=list)


def gather_security_snapshot() -> SecuritySnapshot:
    """Best-effort local sysadmin / security facts for the TUI dashboard."""
    snap = SecuritySnapshot()
    try:
        distro = detect_distro()
        snap.hostname = platform.node() or "localhost"
        snap.distro = distro.id or "unknown"
        snap.version = distro.version_id or ""
        snap.kernel = kernel_release()
        snap.arch = machine_arch()
        snap.ram_mb = read_total_ram_mb()
        snap.is_root = os.geteuid() == 0
    except OSError:
        snap.hostname = platform.node() or "localhost"

    snap.uptime = _uptime()
    snap.loadavg = _loadavg()
    snap.mac = _mac_status()
    snap.firewall = _firewall_status()
    snap.aslr = _aslr_status()
    snap.auto_updates = _auto_updates_status()

    ssh = gather_ssh_inspection()
    snap.sshd = " · ".join(
        f"{k}={v}" for k, v in list(ssh.directives.items())[:3]
    ) or ("installed" if ssh.installed else "not installed")
    snap.listening_hint = ssh.listen_hint
    snap.lines_ssh = ssh.lines

    priv = "root" if snap.is_root else "unprivileged"
    ram = f"{snap.ram_mb} MiB" if snap.ram_mb is not None else "?"
    snap.lines_sys = [
        f"Host      {snap.hostname}",
        f"OS        {snap.distro} {snap.version}  ·  {snap.arch}",
        f"Kernel    {snap.kernel}",
        f"Memory    {ram}  ·  privilege {priv}",
        f"Uptime    {snap.uptime}  ·  load {snap.loadavg}",
    ]
    snap.lines_security = [
        f"MAC       {snap.mac}",
        f"Firewall  {snap.firewall}",
        f"ASLR      {snap.aslr}",
        f"Updates   {snap.auto_updates}",
        f"SSH port  {snap.listening_hint}",
    ]
    return snap


def _read_text(path: str, limit: int = 4096) -> str | None:
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace")[:limit]
    except OSError:
        return None


def _exists(path: str) -> bool:
    return Path(path).exists()


def _uptime() -> str:
    raw = _read_text("/proc/uptime")
    if not raw:
        return "—"
    try:
        seconds = float(raw.split()[0])
    except (ValueError, IndexError):
        return "—"
    days, rem = divmod(int(seconds), 86400)
    hours, rem = divmod(rem, 3600)
    mins, _ = divmod(rem, 60)
    if days:
        return f"{days}d {hours}h {mins}m"
    if hours:
        return f"{hours}h {mins}m"
    return f"{mins}m"


def _loadavg() -> str:
    try:
        a, b, c = os.getloadavg()
        return f"{a:.2f} {b:.2f} {c:.2f}"
    except OSError:
        return "—"


def _mac_status() -> str:
    # AppArmor
    aa = _read_text("/sys/module/apparmor/parameters/enabled")
    if aa is not None:
        enabled = aa.strip() == "Y"
        if not enabled:
            return "AppArmor off"
        status = _read_text("/sys/kernel/security/apparmor/profiles")
        if status is not None:
            enforce = sum(1 for line in status.splitlines() if "(enforce)" in line)
            complain = sum(1 for line in status.splitlines() if "(complain)" in line)
            return f"AppArmor on ({enforce} enforce / {complain} complain)"
        return "AppArmor on"

    # SELinux
    if _exists("/sys/fs/selinux") or _exists("/etc/selinux/config"):
        enforce = _read_text("/sys/fs/selinux/enforce")
        if enforce is not None:
            return "SELinux enforcing" if enforce.strip() == "1" else "SELinux permissive"
        cfg = _read_text("/etc/selinux/config") or ""
        for line in cfg.splitlines():
            if line.startswith("SELINUX="):
                return f"SELinux {line.split('=', 1)[1].strip()}"
        return "SELinux present"
    return "none detected"


def _firewall_status() -> str:
    parts: list[str] = []
    if _exists("/usr/sbin/ufw") or _exists("/usr/bin/ufw"):
        # Status file is more reliable without spawning ufw as root.
        ufw = _read_text("/etc/ufw/ufw.conf") or ""
        enabled = "ENABLED=yes" in ufw.replace(" ", "")
        parts.append(f"ufw {'on' if enabled else 'installed'}")
    if _exists("/usr/bin/firewall-cmd") or _exists("/usr/sbin/firewalld"):
        parts.append("firewalld present")
    if _exists("/usr/sbin/nft") or _exists("/usr/bin/nft"):
        parts.append("nftables")
    if _exists("/usr/sbin/iptables"):
        parts.append("iptables")
    return ", ".join(parts) if parts else "none detected"


def _aslr_status() -> str:
    raw = _read_text("/proc/sys/kernel/randomize_va_space")
    if raw is None:
        return "—"
    val = raw.strip()
    labels = {"0": "off", "1": "conservative", "2": "full"}
    return f"{labels.get(val, val)} ({val})"


def _auto_updates_status() -> str:
    if _exists("/etc/apt/apt.conf.d/20auto-upgrades") or _exists(
        "/etc/apt/apt.conf.d/50unattended-upgrades"
    ):
        conf = _read_text("/etc/apt/apt.conf.d/20auto-upgrades") or ""
        if 'Unattended-Upgrade "1"' in conf:
            return "unattended-upgrades enabled"
        return "unattended-upgrades present"
    if _exists("/etc/dnf/automatic.conf") or _exists("/usr/bin/dnf-automatic"):
        return "dnf-automatic present"
    if _exists("/etc/yum/yum-cron.conf"):
        return "yum-cron present"
    return "not detected"

