# Wardline

All-in-one Linux security scanning TUI that runs proven open-source scanners
(Lynis, Trivy, ClamAV, rkhunter, chkrootkit, AIDE, Nmap, OpenSCAP, and more),
turns their output into one **Finding** format, cross-checks them against each
other, and saves every result in a browsable **Vault**.

**App:** [https://github.com/sohaib1khan/Wardline](https://github.com/sohaib1khan/Wardline)

Works on **Debian/Ubuntu**, **RHEL/Fedora/Rocky**, and **Arch** (and most other
Linux with Python 3.12+). Runs **locally**, via **Docker**, or over **SSH**.

---

## Install (gets you a `wardline` command)

### Fastest — one script (any distro)

```bash
curl -fsSL https://raw.githubusercontent.com/sohaib1khan/Wardline/main/scripts/install.sh | bash
```

That installs [uv](https://docs.astral.sh/uv/) if needed, then installs Wardline
into `~/.local/bin/wardline` (on your PATH for the current user).

**System-wide** (`/usr/local/bin/wardline`, needs sudo):

```bash
curl -fsSL https://raw.githubusercontent.com/sohaib1khan/Wardline/main/scripts/install.sh | bash -s -- --system
```

### Manual — Debian / Ubuntu / RHEL / Fedora / Arch

```bash
# 1) uv (once per machine)
curl -LsSf https://astral.sh/uv/install.sh | sh
export PATH="$HOME/.local/bin:$PATH"

# 2) Wardline command
uv tool install git+https://github.com/sohaib1khan/Wardline.git

# 3) First-time setup
wardline --version
wardline guide
wardline init
wardline doctor
wardline tools list --missing
wardline tools install   # prints apt/dnf/pacman-style hints; confirm before run
wardline                 # launch TUI
```

| Distro family | Notes |
|---------------|--------|
| **Debian / Ubuntu** | `uv tool install …` is enough for the app. Scanner packages via `wardline tools install` (apt). |
| **RHEL / Fedora / Rocky** | Same; scanners via dnf when you run `wardline tools install`. |
| **Arch** | Same; install missing scanners with pacman/AUR as `tools install` suggests. |

Upgrade later:

```bash
uv tool upgrade wardline
```

Optional system link if you used a user install:

```bash
sudo ln -sfn "$(command -v wardline)" /usr/local/bin/wardline
```

### From a local clone (development)

```bash
git clone https://github.com/sohaib1khan/Wardline.git
cd Wardline
./scripts/install.sh          # or: uv tool install --editable .
# ./scripts/install.sh --system
```

---

## Docker (scanner sidecar)

Use Docker when you want scanners bundled in an image while Wardline on the
host drives the scan (`--backend docker`). Host root is mounted **read-only**
at `/host`.

```bash
# Prerequisites: Docker Engine + Wardline installed on the host (above)

wardline docker build          # build wardline-scanner:local
wardline docker up             # start sidecar (network/pid=host, /host:ro)
wardline docker status

wardline scan --backend docker --profile quick

wardline docker down           # stop & remove container
```

Compose alternative (same idea):

```bash
cd Wardline   # if you have a clone
docker compose -f docker/compose.yml build
docker compose -f docker/compose.yml up -d
# … run scans with --backend docker …
docker compose -f docker/compose.yml down
```

---

## Quick usage

```bash
wardline                     # TUI
wardline scan --profile quick
wardline scan --profile network
wardline ports list
wardline ports add 8080/tcp
wardline vault list
wardline vault show <id-suffix>
wardline vault export <id-suffix> --format html -o /tmp/wardline-report.html
```

### TUI keys

| Key | Action |
|-----|--------|
| `k` | Keys rail (toggle · auto-hides) |
| `?` | Help |
| `r` / `n` / `l` | Quick / Network / Launcher |
| `f` / `v` | Findings / Vault (saved results) |
| `p` | Ports CRUD |
| `s` | Settings (**Save all** writes `config.toml`) |
| `Ctrl+P` | Command palette |
| `q` | Quit |

---

## Where reports are stored

| What | Default path (user install) |
|------|-----------------------------|
| Config | `~/.config/wardline/config.toml` |
| Hosts | `~/.config/wardline/hosts.toml` |
| Vault (saved scans) | `~/.local/share/wardline/vault/` |
| Per-scan reports | `…/vault/<host>/<date>_<profile>_<id>/` → `scan.json`, `report.md`, `report.html`, `raw/` |
| Evidence Locker | `~/.local/share/wardline/evidence/` |
| Logs | `~/.local/share/wardline/logs/wardline.log` |

Root install uses `/etc/wardline` and `/var/lib/wardline`.  
Overrides: `WARDLINE_CONFIG_DIR`, `WARDLINE_DATA_DIR`. Directories `0700`, files `0600`.

---

## Safety (non-negotiable)

- **Read-only by default.** Scans never change the scanned system.
- Wardline **never** automatically fixes, deletes, or quarantines anything on
  the scanned host. It reports and suggests; you act.
- Tool installs and Nmap out-of-allowlist targets require explicit confirmation.
- Vault deletes are soft-deletes into `vault/.trash/` after typed confirmation.
- See [SECURITY.md](SECURITY.md).

## Development

```bash
uv sync --group dev
uv run ruff check .
uv run ruff format .
uv run pyright
uv run pytest
pre-commit install
```

## License

MIT — see [LICENSE](LICENSE).
