"""Read-only SSH server / key posture inspection (local files only)."""

from __future__ import annotations

import stat
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(slots=True)
class SshFindingDraft:
    rule_id: str
    severity: str  # critical|high|medium|low|info
    title: str
    location: str
    description: str
    fix_hint: str = ""
    evidence: str = ""


@dataclass
class SshInspection:
    installed: bool = False
    listen_hint: str = "—"
    directives: dict[str, str] = field(default_factory=dict)
    host_keys: list[str] = field(default_factory=list)
    user_keys: list[str] = field(default_factory=list)
    auth_keys_count: int = 0
    auth_keys_path: str = ""
    lines: list[str] = field(default_factory=list)
    drafts: list[SshFindingDraft] = field(default_factory=list)


_INTERESTING = (
    "PermitRootLogin",
    "PasswordAuthentication",
    "PubkeyAuthentication",
    "PermitEmptyPasswords",
    "X11Forwarding",
    "MaxAuthTries",
    "AllowUsers",
    "AllowGroups",
    "ChallengeResponseAuthentication",
    "KbdInteractiveAuthentication",
    "UsePAM",
    "Port",
)


def gather_ssh_inspection(*, home: Path | None = None) -> SshInspection:
    """Inspect sshd_config, host keys, and the current user's ~/.ssh."""
    insp = SshInspection()
    home = home if home is not None else Path.home()
    sshd = Path("/usr/sbin/sshd")
    sshd_alt = Path("/usr/bin/sshd")
    insp.installed = sshd.exists() or sshd_alt.exists()

    conf_text = _read_sshd_config()
    insp.directives = _parse_directives(conf_text)
    insp.host_keys = _list_host_keys()
    insp.listen_hint = _ssh_listen_hint()

    ssh_dir = home / ".ssh"
    priv, pubs, auth_count, auth_path, key_drafts = _inspect_user_ssh(ssh_dir)
    insp.user_keys = priv + pubs
    insp.auth_keys_count = auth_count
    insp.auth_keys_path = auth_path
    insp.drafts.extend(key_drafts)
    insp.drafts.extend(_directive_drafts(insp.directives, insp.installed))

    insp.lines = _format_lines(insp)
    return insp


def _read_sshd_config() -> str:
    chunks: list[str] = []
    main = Path("/etc/ssh/sshd_config")
    text = _read_text(main)
    if text:
        chunks.append(text)
    drop_dir = Path("/etc/ssh/sshd_config.d")
    if drop_dir.is_dir():
        for path in sorted(drop_dir.glob("*.conf")):
            extra = _read_text(path)
            if extra:
                chunks.append(f"\n# --- {path} ---\n{extra}")
    return "\n".join(chunks)


def _parse_directives(text: str) -> dict[str, str]:
    found: dict[str, str] = {}
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        parts = stripped.split(None, 1)
        if len(parts) < 2:
            continue
        key, value = parts[0], parts[1]
        if key in _INTERESTING and key not in found:
            # First wins (sshd first-match semantics for many directives).
            found[key] = value
    return found


def _list_host_keys() -> list[str]:
    root = Path("/etc/ssh")
    if not root.is_dir():
        return []
    out: list[str] = []
    for path in sorted(root.glob("ssh_host_*_key")):
        mode = _mode_octal(path)
        out.append(f"{path.name} mode={mode}")
        if mode not in {"0600", "0400"}:
            # noted via drafts below in gather — host key perms
            pass
    return out


def _inspect_user_ssh(
    ssh_dir: Path,
) -> tuple[list[str], list[str], int, str, list[SshFindingDraft]]:
    drafts: list[SshFindingDraft] = []
    priv: list[str] = []
    pubs: list[str] = []
    auth_count = 0
    auth_path = str(ssh_dir / "authorized_keys")

    if not ssh_dir.is_dir():
        return priv, pubs, auth_count, auth_path, drafts

    dir_mode = _mode_octal(ssh_dir)
    if dir_mode not in {"0700", "0500"}:
        drafts.append(
            SshFindingDraft(
                rule_id="SSH-DOTSSH-PERMS",
                severity="medium",
                title=f"~/.ssh directory mode is {dir_mode} (prefer 0700)",
                location=str(ssh_dir),
                description="World/group-accessible SSH directories can leak keys or authorized_keys.",
                fix_hint="chmod 700 ~/.ssh",
                evidence=f"mode={dir_mode}",
            )
        )

    for path in sorted(ssh_dir.iterdir()):
        if not path.is_file():
            continue
        name = path.name
        mode = _mode_octal(path)
        if name == "authorized_keys" or name == "authorized_keys2":
            try:
                lines = [
                    ln
                    for ln in path.read_text(encoding="utf-8", errors="replace").splitlines()
                    if ln.strip() and not ln.strip().startswith("#")
                ]
            except OSError:
                lines = []
            auth_count = len(lines)
            auth_path = str(path)
            if mode not in {"0600", "0644", "0400"}:
                drafts.append(
                    SshFindingDraft(
                        rule_id="SSH-AUTHKEYS-PERMS",
                        severity="high",
                        title=f"authorized_keys mode is {mode}",
                        location=str(path),
                        description="authorized_keys should typically be 0600 or 0644.",
                        fix_hint=f"chmod 600 {path}",
                        evidence=f"mode={mode} keys={auth_count}",
                    )
                )
            continue
        if name.endswith(".pub"):
            pubs.append(f"{name} mode={mode}")
            continue
        # Likely private key: id_*, *_key without .pub
        if name.startswith("id_") or name.endswith("_key") or name in {"identity"}:
            priv.append(f"{name} mode={mode}")
            if mode not in {"0600", "0400"}:
                drafts.append(
                    SshFindingDraft(
                        rule_id="SSH-PRIVKEY-PERMS",
                        severity="high",
                        title=f"Private key {name} mode is {mode} (prefer 0600)",
                        location=str(path),
                        description="Private SSH keys must not be group/world readable.",
                        fix_hint=f"chmod 600 {path}",
                        evidence=f"mode={mode}",
                    )
                )

    for path in sorted(Path("/etc/ssh").glob("ssh_host_*_key")):
        mode = _mode_octal(path)
        if mode not in {"0600", "0400"}:
            drafts.append(
                SshFindingDraft(
                    rule_id="SSH-HOSTKEY-PERMS",
                    severity="high",
                    title=f"Host key {path.name} mode is {mode}",
                    location=str(path),
                    description="SSH host private keys should be 0600 (or 0400).",
                    fix_hint=f"sudo chmod 600 {path}",
                    evidence=f"mode={mode}",
                )
            )

    return priv, pubs, auth_count, auth_path, drafts


def _directive_drafts(directives: dict[str, str], installed: bool) -> list[SshFindingDraft]:
    if not installed and not directives:
        return []
    drafts: list[SshFindingDraft] = []
    root = (directives.get("PermitRootLogin") or "").lower()
    if root in {"yes", "prohibit-password", "without-password"}:
        sev = "high" if root == "yes" else "medium"
        drafts.append(
            SshFindingDraft(
                rule_id="SSH-PERMIT-ROOT",
                severity=sev,
                title=f"PermitRootLogin is {directives.get('PermitRootLogin')}",
                location="/etc/ssh/sshd_config",
                description="Root SSH login widens blast radius if credentials leak.",
                fix_hint="Set PermitRootLogin no (and use sudo from a named user).",
                evidence=f"PermitRootLogin {directives.get('PermitRootLogin')}",
            )
        )
    pw = (directives.get("PasswordAuthentication") or "").lower()
    if pw == "yes":
        drafts.append(
            SshFindingDraft(
                rule_id="SSH-PASSWORD-AUTH",
                severity="medium",
                title="PasswordAuthentication is yes",
                location="/etc/ssh/sshd_config",
                description="Password auth enables brute-force; prefer key-only where possible.",
                fix_hint="Set PasswordAuthentication no after confirming key access.",
                evidence="PasswordAuthentication yes",
            )
        )
    empty = (directives.get("PermitEmptyPasswords") or "").lower()
    if empty == "yes":
        drafts.append(
            SshFindingDraft(
                rule_id="SSH-EMPTY-PASSWORDS",
                severity="critical",
                title="PermitEmptyPasswords is yes",
                location="/etc/ssh/sshd_config",
                description="Empty passwords allow unauthenticated SSH access.",
                fix_hint="Set PermitEmptyPasswords no",
                evidence="PermitEmptyPasswords yes",
            )
        )
    x11 = (directives.get("X11Forwarding") or "").lower()
    if x11 == "yes":
        drafts.append(
            SshFindingDraft(
                rule_id="SSH-X11-FORWARD",
                severity="low",
                title="X11Forwarding is enabled",
                location="/etc/ssh/sshd_config",
                description="X11 forwarding can expose desktop sessions if misused.",
                fix_hint="Set X11Forwarding no unless required.",
                evidence="X11Forwarding yes",
            )
        )
    return drafts


def _format_lines(insp: SshInspection) -> list[str]:
    if not insp.installed and not insp.directives:
        return ["sshd      not installed / config unreadable"]
    lines = [
        f"sshd      {'installed' if insp.installed else 'config only'}",
        f"Listen    {insp.listen_hint}",
    ]
    for key in _INTERESTING:
        if key in insp.directives:
            lines.append(f"{key:<22} {insp.directives[key]}")
    if insp.host_keys:
        lines.append("Host keys " + ", ".join(insp.host_keys[:4]))
        if len(insp.host_keys) > 4:
            lines.append(f"          (+{len(insp.host_keys) - 4} more)")
    else:
        lines.append("Host keys (none readable under /etc/ssh)")
    if insp.user_keys:
        lines.append("User keys " + ", ".join(insp.user_keys[:5]))
    else:
        lines.append("User keys (none under ~/.ssh)")
    lines.append(f"AuthKeys  {insp.auth_keys_count} key(s) in {insp.auth_keys_path or '—'}")
    if insp.drafts:
        lines.append(f"Flags     {len(insp.drafts)} posture issue(s) — see scan plugin ssh_posture")
    return lines


def _ssh_listen_hint() -> str:
    for path in ("/proc/net/tcp", "/proc/net/tcp6"):
        text = _read_text(Path(path), limit=256_000)
        if not text:
            continue
        for line in text.splitlines()[1:]:
            cols = line.split()
            if len(cols) < 4 or cols[3].upper() != "0A":
                continue
            try:
                port = int(cols[1].rsplit(":", 1)[-1], 16)
            except ValueError:
                continue
            if port == 22:
                return "listening on 22"
    return "22 not observed in /proc/net"


def _read_text(path: Path, limit: int = 256_000) -> str | None:
    try:
        return path.read_text(encoding="utf-8", errors="replace")[:limit]
    except OSError:
        return None


def _mode_octal(path: Path) -> str:
    try:
        return f"{stat.S_IMODE(path.stat().st_mode):04o}"
    except OSError:
        return "????"
