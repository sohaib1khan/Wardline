"""Dashboard — brand, sys/security info, posture, fleet, quick actions."""

from __future__ import annotations

from asyncio import sleep
from typing import ClassVar

from textual.app import ComposeResult
from textual.binding import Binding, BindingType
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import Screen
from textual.widgets import Button, Digits, Footer, Static

from wardline.core.paths import describe_storage_layout
from wardline.tui.screens.launcher import LauncherScreen
from wardline.tui.sysinfo import SecuritySnapshot, gather_security_snapshot
from wardline.tui.widgets.header import WardHeader
from wardline.tui.widgets.logo import LOGO_COMPACT
from wardline.vault.store import VaultStore

_DEMO_SYS = SecuritySnapshot(
    hostname="lab01.example.internal",
    distro="debian",
    version="12",
    kernel="6.1.0-0-amd64",
    arch="x86_64",
    ram_mb=8192,
    is_root=False,
    uptime="3d 4h",
    loadavg="0.10 0.20 0.30",
    mac="AppArmor on (12 enforce / 0 complain)",
    firewall="ufw on, nftables",
    aslr="full (2)",
    sshd="installed · PermitRootLogin=no · PasswordAuth=no",
    auto_updates="unattended-upgrades enabled",
    listening_hint="listening on 22",
    lines_sys=[
        "Host      lab01.example.internal",
        "OS        debian 12  ·  x86_64",
        "Kernel    6.1.0-0-amd64",
        "Memory    8192 MiB  ·  privilege unprivileged",
        "Uptime    3d 4h  ·  load 0.10 0.20 0.30",
    ],
    lines_security=[
        "MAC       AppArmor on (12 enforce / 0 complain)",
        "Firewall  ufw on, nftables",
        "ASLR      full (2)",
        "Updates   unattended-upgrades enabled",
        "SSH port  listening on 22",
    ],
    lines_ssh=[
        "sshd      installed",
        "Listen    listening on 22",
        "PermitRootLogin       no",
        "PasswordAuthentication no",
        "PubkeyAuthentication  yes",
        "Host keys ssh_host_ed25519_key mode=0600",
        "User keys id_ed25519 mode=0600",
        "AuthKeys  1 key(s) in /home/wardline/.ssh/authorized_keys",
    ],
)


class DashboardScreen(Screen[None]):
    # Keys live in the rail (k) / Help — keep Footer free of the full map.
    BINDINGS: ClassVar[list[BindingType]] = [
        Binding("q", "app.quit", "Quit", show=False),
        Binding("r", "quick_scan", "Quick scan", show=False),
        Binding("n", "network_scan", "Network", show=False),
        Binding("l", "open_launcher", "Launcher", show=False),
        Binding("h", "open_hosts", "Hosts", show=False),
        Binding("f", "open_latest_findings", "Findings", show=False),
        Binding("v", "open_vault", "Vault", show=False),
        Binding("p", "open_ports", "Ports", show=False),
        Binding("question_mark", "open_help", "Help", show=False),
    ]

    def compose(self) -> ComposeResult:
        yield WardHeader()
        with VerticalScroll(id="dash-root"):
            yield Static(LOGO_COMPACT, id="dash-brand", markup=False)
            yield Static("", id="dash-meta")

            with Vertical(classes="dash-panel", id="dash-sys"):
                yield Static("System", classes="dash-panel-title")
                yield Static("Loading host…", id="sys-body")

            with Vertical(classes="dash-panel", id="dash-security"):
                yield Static("Security posture (host)", classes="dash-panel-title")
                yield Static("Probing…", id="security-body")

            with Vertical(classes="dash-panel", id="dash-ssh"):
                yield Static("SSH keys & server", classes="dash-panel-title")
                yield Static("Probing…", id="ssh-body")

            with Vertical(classes="dash-panel", id="dash-posture"):
                yield Static("Scan posture", classes="dash-panel-title")
                yield Digits("100", id="posture-digits")
                yield Static("", id="score-meta")

            with Vertical(classes="dash-panel", id="dash-severity"):
                yield Static("Severity (latest scan)", classes="dash-panel-title")
                yield Static("", id="severity-bar")

            with Vertical(classes="dash-panel", id="dash-fleet"):
                yield Static("Fleet", classes="dash-panel-title")
                yield Static("", id="fleet-overview")

            with Vertical(classes="dash-panel", id="dash-recent"):
                yield Static("Recent scans", classes="dash-panel-title")
                yield Static("", id="recent-scans")

            with Vertical(classes="dash-panel", id="dash-storage"):
                yield Static("Where data is stored", classes="dash-panel-title")
                yield Static("", id="storage-body")

            with Horizontal(id="dash-actions"):
                yield Button("Quick scan", variant="primary", id="btn-quick", classes="-primary")
                yield Button("Network scan", id="btn-network")
                yield Button("Scan launcher", id="btn-launch")
                yield Button("Latest findings", id="btn-findings")
                yield Button("Vault", id="btn-vault")
                yield Button("Ports", id="btn-ports")
                yield Button("Hosts", id="btn-hosts")
                yield Button("Help", id="btn-help")
                yield Button("Refresh", id="btn-refresh")
        yield Footer()

    def on_mount(self) -> None:
        self.refresh_dashboard()

    def on_screen_resume(self) -> None:
        self.refresh_dashboard()

    def refresh_dashboard(self) -> None:
        self._refresh_sys_panels()
        self.query_one("#storage-body", Static).update(describe_storage_layout())
        vault: VaultStore = self.app.vault  # type: ignore[attr-defined]
        entries = vault.list_scans(limit=8)
        digits = self.query_one("#posture-digits", Digits)
        meta = self.query_one("#score-meta", Static)
        sev = self.query_one("#severity-bar", Static)
        fleet = self.query_one("#fleet-overview", Static)
        recent = self.query_one("#recent-scans", Static)
        dash_meta = self.query_one("#dash-meta", Static)

        fleet.update(_fleet_overview(vault))

        if not entries:
            digits.update("100")
            meta.update("No scans yet — press [bold]r[/] or Quick scan to populate the Vault.")
            sev.update(_severity_bars(0, 0, 0, 0, 0))
            recent.update("(empty)  ·  tip: ? opens Help · f opens Findings · v Vault")
            dash_meta.update("awaiting first scan  ·  press ? for how-to")
            return

        latest = entries[0]
        reduce_motion = getattr(self.app, "reduce_motion", False)
        if reduce_motion:
            digits.update(f"{latest.posture:03d}")
        else:
            self.run_worker(self._animate_score(latest.posture), exclusive=True)

        dash_meta.update(
            f"{latest.host} · {latest.profile} · "
            f"{latest.started_at.replace('T', ' ')[:16]} · id …{latest.scan_id[-8:]}"
        )
        meta.update(
            f"Latest  …{latest.scan_id[-8:]}  ·  {latest.host}  ·  "
            f"profile {latest.profile}  ·  press [bold]f[/] to view findings"
        )
        sev.update(
            _severity_bars(
                latest.critical,
                latest.high,
                latest.medium,
                latest.low,
                latest.info,
            )
        )
        lines = ["  Press [bold]f[/] for latest findings · [bold]v[/] for all saved scans"]
        for entry in entries[:5]:
            lines.append(
                f"  …{entry.scan_id[-8:]}  {entry.host:16}  "
                f"posture {entry.posture:3}  {entry.profile}"
            )
            lines.append(f"           {entry.path}")
        spark_vals = list(reversed([e.posture for e in entries[:8]]))
        lines.append(f"  Trend  {_sparkline(spark_vals)}")
        recent.update("\n".join(lines))

    def _refresh_sys_panels(self) -> None:
        try:
            if getattr(self.app, "demo_mode", False):
                snap = _DEMO_SYS
            else:
                snap = gather_security_snapshot()
            self.query_one("#sys-body", Static).update("\n".join(snap.lines_sys))
            self.query_one("#security-body", Static).update("\n".join(snap.lines_security))
            self.query_one("#ssh-body", Static).update(
                "\n".join(snap.lines_ssh) if snap.lines_ssh else "—"
            )
        except Exception as exc:
            self.query_one("#sys-body", Static).update(f"Unavailable: {exc}")
            self.query_one("#security-body", Static).update("—")
            self.query_one("#ssh-body", Static).update("—")

    async def _animate_score(self, target: int) -> None:
        digits = self.query_one("#posture-digits", Digits)
        step = max(1, target // 12) if target else 1
        value = 0
        while value < target:
            value = min(target, value + step)
            digits.update(f"{value:03d}")
            await self.app.animator.wait_for_idle()
            await sleep(0.03)
        digits.update(f"{target:03d}")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-quick":
            self.action_quick_scan()
        elif event.button.id == "btn-network":
            self.action_network_scan()
        elif event.button.id == "btn-launch":
            self.action_open_launcher()
        elif event.button.id == "btn-findings":
            self.action_open_latest_findings()
        elif event.button.id == "btn-vault":
            self.action_open_vault()
        elif event.button.id == "btn-ports":
            self.action_open_ports()
        elif event.button.id == "btn-hosts":
            self.action_open_hosts()
        elif event.button.id == "btn-help":
            self.action_open_help()
        elif event.button.id == "btn-refresh":
            self.refresh_dashboard()

    def action_quick_scan(self) -> None:
        self.app.open_live_scan(  # type: ignore[attr-defined]
            profile="quick",
            plugins=["ss_baseline", "ssh_posture", "lynis", "trivy", "patch_status"],
        )

    def action_network_scan(self) -> None:
        self.app.open_live_scan(  # type: ignore[attr-defined]
            profile="network",
            plugins=["ss_baseline", "ssh_posture", "nmap"],
        )

    def action_open_launcher(self) -> None:
        self.app.push_screen(LauncherScreen())

    def action_open_latest_findings(self) -> None:
        from wardline.tui.screens.findings import FindingsScreen

        self.app.push_screen(FindingsScreen())

    def action_open_vault(self) -> None:
        from wardline.tui.screens.vault_browser import VaultScreen

        self.app.push_screen(VaultScreen())

    def action_open_ports(self) -> None:
        from wardline.tui.screens.ports import PortsScreen

        self.app.push_screen(PortsScreen())

    def action_open_hosts(self) -> None:
        from wardline.tui.screens.hosts import HostsScreen

        self.app.push_screen(HostsScreen())

    def action_open_help(self) -> None:
        from wardline.tui.screens.help import HelpScreen

        self.app.push_screen(HelpScreen())


def _fleet_overview(vault: VaultStore) -> str:
    by_host: dict[str, int] = {}
    for entry in vault.list_scans(limit=50):
        if entry.host not in by_host:
            by_host[entry.host] = entry.posture
    if not by_host:
        return "(no hosts scanned yet)"
    lines = []
    for host, posture in sorted(by_host.items()):
        bar = _mini_bar(posture, 100, width=12)
        grade = _posture_grade(posture)
        lines.append(f"  {host:22}  {bar}  {posture:3}  {grade}")
    return "\n".join(lines)


def _severity_bars(crit: int, high: int, med: int, low: int, info: int) -> str:
    total = max(1, crit + high + med + low + info)
    rows = [
        ("crit", crit, "red"),
        ("high", high, "orange1"),
        ("med ", med, "yellow"),
        ("low ", low, "green"),
        ("info", info, "cyan"),
    ]
    lines: list[str] = []
    for label, count, color in rows:
        filled = round((count / total) * 16) if count else 0
        bar = "█" * filled + "░" * (16 - filled)
        lines.append(f"  [{color}]{label}[/{color}]  {bar}  {count}")
    lines.append(f"  total findings  {crit + high + med + low + info}")
    return "\n".join(lines)


def _mini_bar(value: int, maximum: int, *, width: int = 10) -> str:
    if maximum <= 0:
        return "░" * width
    filled = max(0, min(width, round(value / maximum * width)))
    return "█" * filled + "░" * (width - filled)


def _posture_grade(score: int) -> str:
    if score >= 90:
        return "strong"
    if score >= 70:
        return "fair"
    if score >= 40:
        return "weak"
    return "critical"


def _sparkline(values: list[int]) -> str:
    if not values:
        return "—"
    blocks = "▁▂▃▄▅▆▇█"
    lo = min(values)
    hi = max(values)
    span = max(1, hi - lo)
    out: list[str] = []
    for v in values:
        idx = int((v - lo) / span * (len(blocks) - 1))
        out.append(blocks[idx])
    return "".join(out)
