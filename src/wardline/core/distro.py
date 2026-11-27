"""Distro and package-manager detection from /etc/os-release."""

from __future__ import annotations

import platform
import re
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

OS_RELEASE_PATH = Path("/etc/os-release")


class PackageManager(StrEnum):
    APT = "apt"
    DNF = "dnf"
    YUM = "yum"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class DistroInfo:
    id: str
    name: str
    version_id: str
    version_codename: str
    pretty_name: str
    id_like: tuple[str, ...]
    package_manager: PackageManager
    family: str  # debian | rhel | unknown

    @property
    def is_debian_family(self) -> bool:
        return self.family == "debian"

    @property
    def is_rhel_family(self) -> bool:
        return self.family == "rhel"


_DEBIAN_IDS = frozenset({"debian", "ubuntu", "linuxmint", "pop", "raspbian", "kali"})
_RHEL_IDS = frozenset(
    {
        "rhel",
        "centos",
        "rocky",
        "almalinux",
        "fedora",
        "ol",
        "oracle",
        "amzn",
        "scientific",
    }
)


def parse_os_release(text: str) -> dict[str, str]:
    """Parse os-release key=value content into a dict."""
    result: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        # Unescape common sequences used in os-release.
        value = value.replace("\\$", "$").replace('\\"', '"').replace("\\\\", "\\")
        result[key.strip()] = value
    return result


def _classify_family(distro_id: str, id_like: tuple[str, ...]) -> str:
    candidates = (distro_id, *id_like)
    for candidate in candidates:
        if candidate in _DEBIAN_IDS or candidate.startswith("debian"):
            return "debian"
        if candidate in _RHEL_IDS or candidate in {"fedora", "rhel"}:
            return "rhel"
    # id_like may contain space-joined tokens like "rhel fedora"
    joined = " ".join(candidates)
    if re.search(r"\b(debian|ubuntu)\b", joined):
        return "debian"
    if re.search(r"\b(rhel|fedora|centos)\b", joined):
        return "rhel"
    return "unknown"


def _package_manager_for(family: str, distro_id: str) -> PackageManager:
    del distro_id  # reserved for future yum-vs-dnf heuristics
    if family == "debian":
        return PackageManager.APT
    if family == "rhel":
        return PackageManager.DNF
    return PackageManager.UNKNOWN


def detect_distro(os_release_path: Path | None = None) -> DistroInfo:
    """Read os-release and return structured distro info.

    Raises ``FileNotFoundError`` if the file is missing, with a friendly message.
    """
    path = os_release_path if os_release_path is not None else OS_RELEASE_PATH
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise FileNotFoundError(
            f"Cannot detect distro: {path} not found. "
            "Wardline currently supports Linux hosts with an os-release file."
        ) from exc
    except OSError as exc:
        raise OSError(f"Cannot read distro info from {path}: {exc}") from exc

    fields = parse_os_release(text)
    distro_id = fields.get("ID", "unknown").lower()
    id_like_raw = fields.get("ID_LIKE", "")
    id_like = tuple(part.lower() for part in id_like_raw.split() if part)
    family = _classify_family(distro_id, id_like)

    return DistroInfo(
        id=distro_id,
        name=fields.get("NAME", distro_id),
        version_id=fields.get("VERSION_ID", ""),
        version_codename=fields.get("VERSION_CODENAME", ""),
        pretty_name=fields.get("PRETTY_NAME", fields.get("NAME", distro_id)),
        id_like=id_like,
        package_manager=_package_manager_for(family, distro_id),
        family=family,
    )


def kernel_release() -> str:
    return platform.release()


def machine_arch() -> str:
    return platform.machine()
