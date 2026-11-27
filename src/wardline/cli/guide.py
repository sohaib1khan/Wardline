"""Long-form setup and usage guide for `wardline guide`."""

from __future__ import annotations

from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel

from wardline import __version__
from wardline.core.paths import (
    config_file_path,
    describe_storage_layout,
    get_config_dir,
    get_data_dir,
)
from wardline.meta import APP_NAME, DOCS_URL, ISSUES_URL, REPO_GIT, REPO_URL

_GUIDE = f"""\
# {APP_NAME} setup & usage

**App:** [{REPO_URL}]({REPO_URL})
**Clone:** `{REPO_GIT}`
**Issues:** [{ISSUES_URL}]({ISSUES_URL})
**Version:** {__version__}

## 1. Install the `wardline` command (Debian / RHEL / Arch)

### One script

```bash
curl -fsSL https://raw.githubusercontent.com/sohaib1khan/Wardline/main/scripts/install.sh | bash
# system-wide (/usr/local/bin):
curl -fsSL https://raw.githubusercontent.com/sohaib1khan/Wardline/main/scripts/install.sh | bash -s -- --system
```

### Manual (any distro)

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
export PATH="$HOME/.local/bin:$PATH"
uv tool install git+{REPO_GIT}
wardline --version
```

User install path: `~/.local/bin/wardline`. Optional system link:

```bash
sudo ln -sfn "$(command -v wardline)" /usr/local/bin/wardline
```

## 2. First-time setup

```bash
wardline init
wardline doctor
wardline tools list --missing
wardline tools install   # shows distro install commands; type install to run
wardline
```

Config: `{get_config_dir()}` (`WARDLINE_CONFIG_DIR`).
Data / Vault: `{get_data_dir()}` (`WARDLINE_DATA_DIR`).

## 3. Docker (optional scanner sidecar)

```bash
wardline docker build
wardline docker up
wardline scan --backend docker --profile quick
wardline docker down
```

Host root is mounted read-only at `/host` inside the container.

## 4. Launch & keys

```bash
wardline               # TUI
wardline --help
```

| Key | Action |
|-----|--------|
| `?` | Help |
| `r` / `n` / `l` | Quick / Network / Launcher |
| `f` / `v` | Findings / Vault |
| `p` | Ports |
| `s` | Settings (Save writes config.toml) |
| `Ctrl+P` | Palette |
| `q` | Quit |

## 5. CLI scanning

```bash
wardline scan --profile quick
wardline scan --profile network
wardline ports add 8080/tcp
wardline vault list
wardline vault export <id> --format html -o /tmp/report.html
```

## 6. Where reports live

Vault folders contain `scan.json`, `report.md`, `report.html`, and `raw/`.
See TUI Vault → Show paths. Config file: `{config_file_path()}`

## 7. More

- README: {DOCS_URL}
- Security: {REPO_URL}/blob/main/SECURITY.md
"""


def run_guide(*, console: Console | None = None) -> int:
    console = console or Console()
    console.print(
        Panel.fit(
            f"[bold]{APP_NAME}[/]  ·  setup & usage guide\n[link={REPO_URL}]{REPO_URL}[/link]",
            border_style="cyan",
        )
    )
    console.print(Markdown(_GUIDE))
    console.print()
    console.print("[bold]Storage on this machine[/]")
    console.print(describe_storage_layout())
    console.print()
    console.print(f"[dim]Config file:[/] {config_file_path()}")
    return 0
