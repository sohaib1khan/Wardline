"""Built-in scan profiles (plugin lists)."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Profile:
    name: str
    description: str
    plugins: tuple[str, ...]


PROFILES: dict[str, Profile] = {
    "quick": Profile(
        name="quick",
        description="Fast posture check: listeners, Lynis, Trivy, patch status.",
        plugins=("ss_baseline", "ssh_posture", "lynis", "trivy", "patch_status"),
    ),
    "standard": Profile(
        name="standard",
        description="Quick plus rootkit/integrity/persistence checks.",
        plugins=(
            "ss_baseline",
            "ssh_posture",
            "lynis",
            "trivy",
            "rkhunter",
            "chkrootkit",
            "aide",
            "persistence",
            "pkg_verify",
        ),
    ),
    "deep": Profile(
        name="deep",
        description="Standard plus malware, network, and compliance scanners.",
        plugins=(
            "ss_baseline",
            "ssh_posture",
            "lynis",
            "trivy",
            "rkhunter",
            "chkrootkit",
            "aide",
            "persistence",
            "pkg_verify",
            "clamav",
            "nmap",
            "openscap",
        ),
    ),
    "compliance": Profile(
        name="compliance",
        description="OpenSCAP/USG and Lynis.",
        plugins=("openscap", "lynis"),
    ),
    "incident": Profile(
        name="incident",
        description="Read-only incident triage (no DB updates / baselines).",
        plugins=(
            "aide",
            "rkhunter",
            "chkrootkit",
            "pkg_verify",
            "persistence",
            "ss_baseline",
        ),
    ),
    "network": Profile(
        name="network",
        description="Local listeners (ss) plus allowlisted Nmap service scan.",
        plugins=("ss_baseline", "ssh_posture", "nmap"),
    ),
}


def get_profile(name: str) -> Profile:
    key = name.strip().lower()
    try:
        return PROFILES[key]
    except KeyError as exc:
        known = ", ".join(sorted(PROFILES))
        raise KeyError(f"unknown profile {name!r}; choose one of: {known}") from exc


def resolve_plugin_names(
    *,
    profile: str | None = None,
    plugins: list[str] | None = None,
) -> list[str]:
    """Resolve the ordered plugin list for a scan.

    Explicit ``plugins`` wins; otherwise the named profile is used.
    Unknown plugins in a profile are skipped later by the engine when missing
    from the registry.
    """
    if plugins:
        return [p.strip() for p in plugins if p.strip()]
    name = profile or "quick"
    return list(get_profile(name).plugins)
