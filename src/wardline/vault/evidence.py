"""Evidence Locker — opt-in, copy-only collection of flagged files."""

from __future__ import annotations

import hashlib
import json
import shutil
import stat
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from wardline.core.config import EvidenceConfig
from wardline.core.paths import DIR_MODE, ensure_dir, evidence_root, write_private_file
from wardline.vault.safety import VaultSafetyError, assert_inside_vault

COPY_MODE = 0o400
META_NAME = "metadata.json"


@dataclass(slots=True)
class EvidenceItem:
    sha256: str
    original_path: str
    copy_path: str
    size: int
    mode: int
    mtime: float
    owner: str
    finding_id: str
    scan_id: str
    copied_at: str
    metadata_path: str


class EvidenceError(ValueError):
    """Raised when evidence copy is refused (disabled, too large, missing, etc.)."""


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _total_bytes(root: Path) -> int:
    total = 0
    if not root.exists():
        return 0
    for path in root.rglob("*"):
        if path.is_file() and not path.is_symlink():
            try:
                total += path.stat().st_size
            except OSError:
                continue
    return total


class EvidenceLocker:
    """Copy-only evidence store under ``<data>/evidence/``."""

    def __init__(
        self,
        root: Path | None = None,
        *,
        config: EvidenceConfig | None = None,
    ) -> None:
        self.root = (root if root is not None else evidence_root()).resolve()
        ensure_dir(self.root, mode=DIR_MODE)
        ensure_dir(self.root / ".trash", mode=DIR_MODE)
        self.config = config or EvidenceConfig()

    def list_items(self) -> list[EvidenceItem]:
        items: list[EvidenceItem] = []
        if not self.root.exists():
            return items
        for child in sorted(self.root.iterdir()):
            if not child.is_dir() or child.name.startswith("."):
                continue
            meta_path = child / META_NAME
            if not meta_path.is_file():
                continue
            try:
                data = json.loads(meta_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            items.append(_item_from_meta(data, meta_path=str(meta_path)))
        return items

    def get(self, sha256: str) -> EvidenceItem:
        meta_path = assert_inside_vault(self.root / sha256 / META_NAME, self.root)
        if not meta_path.is_file():
            raise LookupError(f"evidence not found: {sha256}")
        data = json.loads(meta_path.read_text(encoding="utf-8"))
        return _item_from_meta(data, meta_path=str(meta_path))

    def copy_file(
        self,
        source: Path,
        *,
        finding_id: str,
        scan_id: str,
    ) -> EvidenceItem:
        """Copy ``source`` into the locker. Never modifies the original."""
        if not self.config.enabled:
            raise EvidenceError(
                "Evidence Locker is disabled. Enable evidence.enabled in settings."
            )
        src = source.expanduser()
        if not src.is_file() or src.is_symlink():
            raise EvidenceError(f"refusing non-regular file: {source}")

        st = src.stat()
        size = st.st_size
        max_bytes = self.config.max_file_mb * 1024 * 1024
        if size > max_bytes:
            raise EvidenceError(
                f"file exceeds max_file_mb ({self.config.max_file_mb} MiB): {source}"
            )
        total_cap = self.config.max_total_mb * 1024 * 1024
        if _total_bytes(self.root) + size > total_cap:
            raise EvidenceError(
                f"Evidence Locker would exceed max_total_mb ({self.config.max_total_mb} MiB)"
            )

        # Capture original identity before copy.
        before_hash = _sha256_file(src)
        before_mtime = st.st_mtime
        before_mode = stat.S_IMODE(st.st_mode)

        dest_dir = ensure_dir(self.root / before_hash, mode=DIR_MODE)
        assert_inside_vault(dest_dir, self.root)
        dest_file = dest_dir / src.name
        # Copy without following symlinks; do not preserve ownership mutation of source.
        shutil.copyfile(src, dest_file, follow_symlinks=False)
        dest_file.chmod(COPY_MODE)

        # Verify original untouched.
        after_st = src.stat()
        after_hash = _sha256_file(src)
        if after_hash != before_hash or after_st.st_mtime != before_mtime:
            # Best-effort cleanup of the copy; original must remain authoritative.
            dest_file.unlink(missing_ok=True)
            raise EvidenceError("original file changed during copy — aborted")
        if stat.S_IMODE(after_st.st_mode) != before_mode:
            dest_file.unlink(missing_ok=True)
            raise EvidenceError("original file mode changed during copy — aborted")

        owner = str(after_st.st_uid)
        try:
            import pwd

            owner = pwd.getpwuid(after_st.st_uid).pw_name
        except (KeyError, ImportError, OSError):
            pass

        copied_at = datetime.now(UTC).isoformat()
        meta: dict[str, Any] = {
            "sha256": before_hash,
            "original_path": str(src.resolve()),
            "copy_path": str(dest_file.resolve()),
            "size": size,
            "mode": before_mode,
            "mtime": before_mtime,
            "owner": owner,
            "finding_id": finding_id,
            "scan_id": scan_id,
            "copied_at": copied_at,
        }
        meta_path = dest_dir / META_NAME
        write_private_file(meta_path, json.dumps(meta, indent=2) + "\n")
        return _item_from_meta(meta, meta_path=str(meta_path))

    def soft_delete(self, sha256: str, *, confirm_id: str) -> Path:
        """Move an evidence directory into ``evidence/.trash/``."""
        short = sha256[:8]
        if confirm_id.strip() not in {sha256, short, sha256[:12]}:
            raise VaultSafetyError(
                f"confirmation mismatch: type the sha256 (or first 8 chars {short})"
            )
        src_dir = assert_inside_vault(self.root / sha256, self.root)
        if not src_dir.is_dir():
            raise VaultSafetyError(f"evidence path is not a directory: {src_dir}")
        trash = ensure_dir(self.root / ".trash", mode=DIR_MODE)
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        dest = trash / f"{stamp}_{sha256[:12]}"
        n = 1
        while dest.exists():
            dest = trash / f"{stamp}_{sha256[:12]}_{n}"
            n += 1
        assert_inside_vault(dest, self.root)
        shutil.move(str(src_dir), str(dest))
        return dest


def _item_from_meta(data: dict[str, Any], *, meta_path: str) -> EvidenceItem:
    return EvidenceItem(
        sha256=str(data["sha256"]),
        original_path=str(data["original_path"]),
        copy_path=str(data["copy_path"]),
        size=int(data["size"]),
        mode=int(data["mode"]),
        mtime=float(data["mtime"]),
        owner=str(data.get("owner", "")),
        finding_id=str(data.get("finding_id", "")),
        scan_id=str(data.get("scan_id", "")),
        copied_at=str(data.get("copied_at", "")),
        metadata_path=meta_path,
    )
