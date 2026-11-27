"""Evidence Locker — copy-only; original hash/mode/mtime unchanged."""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from wardline.core.config import EvidenceConfig
from wardline.vault.evidence import EvidenceError, EvidenceLocker, _sha256_file


def test_copy_does_not_modify_original(tmp_path: Path) -> None:
    src = tmp_path / "flagged.bin"
    payload = b"wardline-evidence-fixture-contents\n"
    src.write_bytes(payload)
    src.chmod(0o644)
    os.utime(src, (1_700_000_000, 1_700_000_000))

    before_hash = _sha256_file(src)
    before_st = src.stat()
    before_mode = stat.S_IMODE(before_st.st_mode)
    before_mtime = before_st.st_mtime

    locker = EvidenceLocker(
        tmp_path / "evidence",
        config=EvidenceConfig(enabled=True, max_file_mb=1, max_total_mb=10),
    )
    item = locker.copy_file(src, finding_id="finding123", scan_id="scan123")

    after_st = src.stat()
    assert _sha256_file(src) == before_hash
    assert stat.S_IMODE(after_st.st_mode) == before_mode
    assert after_st.st_mtime == before_mtime
    assert src.read_bytes() == payload

    assert item.sha256 == before_hash
    copy = Path(item.copy_path)
    assert copy.is_file()
    assert copy.read_bytes() == payload
    assert stat.S_IMODE(copy.stat().st_mode) == 0o400
    assert copy.resolve() != src.resolve()


def test_disabled_locker_refuses(tmp_path: Path) -> None:
    src = tmp_path / "x.txt"
    src.write_text("x", encoding="utf-8")
    locker = EvidenceLocker(tmp_path / "evidence", config=EvidenceConfig(enabled=False))
    with pytest.raises(EvidenceError, match="disabled"):
        locker.copy_file(src, finding_id="f", scan_id="s")


def test_oversized_refused(tmp_path: Path) -> None:
    src = tmp_path / "big.bin"
    src.write_bytes(b"b" * (1024 * 1024 + 10))
    locker = EvidenceLocker(
        tmp_path / "evidence",
        config=EvidenceConfig(enabled=True, max_file_mb=1, max_total_mb=10),
    )
    with pytest.raises(EvidenceError, match="max_file_mb"):
        locker.copy_file(src, finding_id="f", scan_id="s")


def test_soft_delete_moves_to_trash(tmp_path: Path) -> None:
    src = tmp_path / "y.txt"
    src.write_text("y", encoding="utf-8")
    locker = EvidenceLocker(tmp_path / "evidence", config=EvidenceConfig(enabled=True))
    item = locker.copy_file(src, finding_id="f", scan_id="s")
    dest = locker.soft_delete(item.sha256, confirm_id=item.sha256[:8])
    assert dest.exists()
    assert not (tmp_path / "evidence" / item.sha256).exists()
    assert src.read_text(encoding="utf-8") == "y"
