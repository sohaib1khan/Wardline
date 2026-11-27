"""SSH inspection helpers."""

from __future__ import annotations

from pathlib import Path

from wardline.core.ssh_inspect import gather_ssh_inspection


def test_gather_ssh_inspection_runs() -> None:
    insp = gather_ssh_inspection()
    assert isinstance(insp.lines, list)
    assert insp.lines
    assert isinstance(insp.drafts, list)


def test_user_key_perms_flagged(tmp_path: Path) -> None:
    ssh = tmp_path / ".ssh"
    ssh.mkdir(mode=0o755)
    key = ssh / "id_ed25519"
    key.write_text("fake", encoding="utf-8")
    key.chmod(0o644)
    insp = gather_ssh_inspection(home=tmp_path)
    assert any(d.rule_id == "SSH-PRIVKEY-PERMS" for d in insp.drafts)
    assert any(d.rule_id == "SSH-DOTSSH-PERMS" for d in insp.drafts)
