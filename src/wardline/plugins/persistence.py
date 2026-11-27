"""Read-only persistence surface snapshot + diff vs previous scan."""

from __future__ import annotations

import json
from typing import Any

from wardline.backends.base import Backend, CommandResult
from wardline.core.distro import DistroInfo
from wardline.core.models import Category, Finding, PluginStatus, Severity
from wardline.plugins.base import DetectResult, ParseResult, Plugin, default_capabilities

# Portable collector — ROOT is substituted for Docker (/host) vs local (/).
_COLLECT_SCRIPT = r"""
set -e
python3 - <<'PY'
import json, os, glob
from pathlib import Path

ROOT = "__WARDLINE_ROOT__"
if ROOT in ("", "/"):
    root = ""
else:
    root = ROOT.rstrip("/")

def p(*parts):
    return str(Path(root, *parts)) if root else str(Path(*parts))

data = {
  "cron_system": [],
  "timers": [],
  "authorized_keys": {},
  "uid0_users": [],
  "users": [],
}

for pattern in [p("etc/cron.d") + "/*", p("etc/cron.daily") + "/*",
                p("etc/cron.hourly") + "/*", p("etc/crontab")]:
    for path in sorted(glob.glob(pattern)):
        if os.path.isfile(path):
            data["cron_system"].append(path)

timer_dir = Path(p("etc/systemd/system"))
if timer_dir.exists():
    for path in sorted(timer_dir.glob("*.timer")):
        data["timers"].append(path.name)
lib_timers = Path(p("usr/lib/systemd/system"))
if lib_timers.exists():
    for path in sorted(lib_timers.glob("*.timer")):
        name = path.name
        if name not in data["timers"]:
            data["timers"].append(name)

passwd = Path(p("etc/passwd"))
if passwd.is_file():
    for line in passwd.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line or line.startswith("#"):
            continue
        parts = line.split(":")
        if len(parts) < 6:
            continue
        name, _pw, uid_s, _gid, _gecos, home, _shell = parts[0], parts[1], parts[2], parts[3], parts[4], parts[5], parts[6] if len(parts) > 6 else ""
        data["users"].append(name)
        try:
            uid = int(uid_s)
        except ValueError:
            continue
        if uid == 0:
            data["uid0_users"].append(name)
        ssh = Path(home) / ".ssh" / "authorized_keys"
        if root and not str(home).startswith(root):
            ssh = Path(root) / home.lstrip("/") / ".ssh" / "authorized_keys"
        if ssh.is_file():
            try:
                keys = [ln.strip() for ln in ssh.read_text(encoding="utf-8", errors="replace").splitlines() if ln.strip() and not ln.startswith("#")]
                data["authorized_keys"][name] = keys
            except OSError:
                pass

print(json.dumps(data, sort_keys=True))
PY
"""


class PersistencePlugin(Plugin):
    name = "persistence"
    display_name = "Persistence"
    category = Category.PERSISTENCE
    description = "Read-only cron/timer/SSH key/UID0 inventory with new-entry detection."
    needs_root = True  # reading other users' authorized_keys typically needs root
    default_timeout = 300.0
    capabilities = default_capabilities()

    async def detect(self, backend: Backend) -> DetectResult:
        # Uses python3 + standard Linux paths; treat as installed if python3 exists.
        path = await backend.which("python3")
        if not path:
            return DetectResult(installed=False)
        return DetectResult(installed=True, version="read-only", path=path)

    def install_hint(self, distro: DistroInfo) -> list[str]:
        del distro
        return ["# Requires python3 on the target (usually already present)"]

    def build_commands(
        self, backend: Backend, options: dict[str, Any] | None = None
    ) -> list[list[str]]:
        del options
        root = backend.path("/")
        script = _COLLECT_SCRIPT.replace("__WARDLINE_ROOT__", root)
        return [["sh", "-c", script]]

    def interpret_exit_code(self, code: int) -> PluginStatus:
        return PluginStatus.OK if code == 0 else PluginStatus.FAILED

    async def collect_raw_output(self, backend: Backend, results: list[CommandResult]) -> str:
        del backend
        parts = []
        for result in results:
            if result.stdout:
                parts.append(result.stdout)
            if result.stderr:
                parts.append(result.stderr)
        return "\n".join(parts).strip()

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
        findings: list[Finding] = []
        snapshot = _extract_json(raw_output) or {}
        previous = options.get("previous_persistence") or {}

        if not snapshot:
            return ParseResult(
                findings=[
                    Finding(
                        scan_id=scan_id,
                        host=host,
                        plugin=self.name,
                        rule_id="PERS-PARSE",
                        category=Category.PERSISTENCE,
                        severity=Severity.LOW,
                        title="Could not parse persistence snapshot",
                        location="persistence",
                        evidence=raw_output[:400],
                    )
                ]
            )

        if previous:
            findings.extend(
                _diff_findings(snapshot, previous, scan_id=scan_id, host=host, plugin=self.name)
            )
        else:
            # First run: still flag extra UID0 users immediately.
            for user in snapshot.get("uid0_users") or []:
                if user != "root":
                    findings.append(
                        Finding(
                            scan_id=scan_id,
                            host=host,
                            plugin=self.name,
                            rule_id=f"PERS-UID0-{user}",
                            category=Category.PERSISTENCE,
                            severity=Severity.HIGH,
                            title=f"UID 0 user besides root: {user}",
                            location=user,
                            evidence=user,
                            fix_hint="Investigate unexpected UID 0 accounts.",
                        )
                    )

        return ParseResult(findings=findings, extras={"persistence": snapshot})


def _extract_json(raw: str) -> dict[str, Any] | None:
    text = raw.strip()
    start = text.find("{")
    end = text.rfind("}")
    if start < 0 or end <= start:
        return None
    try:
        data = json.loads(text[start : end + 1])
        return data if isinstance(data, dict) else None
    except json.JSONDecodeError:
        return None


def _diff_findings(
    current: dict[str, Any],
    previous: dict[str, Any],
    *,
    scan_id: str,
    host: str,
    plugin: str,
) -> list[Finding]:
    findings: list[Finding] = []

    def new_items(key: str) -> list[str]:
        cur = set(current.get(key) or [])
        prev = set(previous.get(key) or [])
        return sorted(cur - prev)

    for item in new_items("cron_system"):
        findings.append(
            Finding(
                scan_id=scan_id,
                host=host,
                plugin=plugin,
                rule_id=f"PERS-CRON-{item}",
                category=Category.PERSISTENCE,
                severity=Severity.MEDIUM,
                title=f"New cron entry: {item}",
                location=item,
                evidence=item,
            )
        )
    for item in new_items("timers"):
        findings.append(
            Finding(
                scan_id=scan_id,
                host=host,
                plugin=plugin,
                rule_id=f"PERS-TIMER-{item}",
                category=Category.PERSISTENCE,
                severity=Severity.MEDIUM,
                title=f"New systemd timer: {item}",
                location=item,
                evidence=item,
            )
        )
    for item in new_items("users"):
        findings.append(
            Finding(
                scan_id=scan_id,
                host=host,
                plugin=plugin,
                rule_id=f"PERS-USER-{item}",
                category=Category.PERSISTENCE,
                severity=Severity.MEDIUM,
                title=f"New user account: {item}",
                location=item,
                evidence=item,
            )
        )
    for item in new_items("uid0_users"):
        if item == "root":
            continue
        findings.append(
            Finding(
                scan_id=scan_id,
                host=host,
                plugin=plugin,
                rule_id=f"PERS-UID0-{item}",
                category=Category.PERSISTENCE,
                severity=Severity.HIGH,
                title=f"New UID 0 user: {item}",
                location=item,
                evidence=item,
                fix_hint="Investigate unexpected UID 0 accounts immediately.",
            )
        )

    prev_keys = previous.get("authorized_keys") or {}
    cur_keys = current.get("authorized_keys") or {}
    for user, keys in cur_keys.items():
        old = set(prev_keys.get(user) or [])
        for key in keys:
            if key not in old:
                findings.append(
                    Finding(
                        scan_id=scan_id,
                        host=host,
                        plugin=plugin,
                        rule_id=f"PERS-KEY-{user}-{hash(key) & 0xFFFF:x}",
                        category=Category.PERSISTENCE,
                        severity=Severity.HIGH,
                        title=f"New authorized_keys entry for {user}",
                        location=f"~{user}/.ssh/authorized_keys",
                        evidence=key[:200],
                        fix_hint="Verify the new SSH key was intentionally added.",
                    )
                )
    return findings
