"""Vault path safety — the only delete path moves reports into ``.trash/``."""

from __future__ import annotations

import shutil
from datetime import UTC, datetime
from pathlib import Path

from wardline.core.paths import DIR_MODE, ensure_dir


class VaultSafetyError(ValueError):
    """Raised when a path escapes the Vault root or delete rules are violated."""


def assert_inside_vault(path: Path, vault_root: Path) -> Path:
    """Resolve ``path`` and refuse unless it is strictly inside ``vault_root``.

    Protects against ``..``, absolute escapes, and symlink tricks that would
    resolve outside the Vault.
    """
    root = vault_root.resolve()
    # Resolve the candidate; if it does not exist yet, resolve parent + name.
    try:
        resolved = path.resolve(strict=True)
    except FileNotFoundError:
        resolved = path.expanduser().resolve(strict=False)

    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise VaultSafetyError(
            f"refusing path outside Vault: {path} (resolved {resolved}, vault {root})"
        ) from exc

    # Extra symlink guard: if any parent is a symlink leaving the vault, reject.
    current = resolved
    while True:
        if current == root:
            break
        if current.is_symlink():
            link_target = current.resolve()
            try:
                link_target.relative_to(root)
            except ValueError as exc:
                raise VaultSafetyError(
                    f"refusing symlinked path outside Vault: {path} -> {link_target}"
                ) from exc
        if current.parent == current:
            break
        current = current.parent

    return resolved


def trash_dir(vault_root: Path) -> Path:
    path = ensure_dir(vault_root / ".trash", mode=DIR_MODE)
    assert_inside_vault(path, vault_root)
    return path


def soft_delete_report(report_dir: Path, vault_root: Path) -> Path:
    """Move a report directory into ``vault/.trash/`` (never ``rm``).

    Returns the destination path under ``.trash/``.
    """
    resolved = assert_inside_vault(report_dir, vault_root)
    root = vault_root.resolve()
    trash = trash_dir(root)

    if resolved == root:
        raise VaultSafetyError("refusing to delete the Vault root")
    if resolved == trash or trash in resolved.parents:
        raise VaultSafetyError("refusing to soft-delete inside .trash itself")

    if not resolved.is_dir():
        raise VaultSafetyError(f"report path is not a directory: {resolved}")

    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    dest = trash / f"{stamp}_{resolved.name}"
    # Ensure uniqueness.
    n = 1
    while dest.exists():
        dest = trash / f"{stamp}_{resolved.name}_{n}"
        n += 1

    assert_inside_vault(dest, root)
    shutil.move(str(resolved), str(dest))
    return dest


def empty_trash(vault_root: Path, *, confirm: bool = False) -> int:
    """Permanently remove everything under ``.trash/``. Requires confirm=True."""
    if not confirm:
        raise VaultSafetyError("empty_trash requires confirm=True")
    trash = trash_dir(vault_root)
    removed = 0
    for child in list(trash.iterdir()):
        assert_inside_vault(child, vault_root.resolve())
        if child.is_dir() and not child.is_symlink():
            shutil.rmtree(child)
        elif child.is_file() and not child.is_symlink():
            child.unlink()
        else:
            # Symlinks / oddities: unlink only after safety check.
            child.unlink(missing_ok=True)
        removed += 1
    return removed
