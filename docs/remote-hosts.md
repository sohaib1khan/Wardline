# Remote hosts (SSH)

Wardline scans remote Linux hosts **agentlessly** over SSH.

## Safety

- **Key auth only** — identity file and/or ssh-agent. No passwords.
- **Strict `known_hosts`** — unknown keys are refused until you confirm the fingerprint
  (`wardline hosts accept-key` or the TUI dialog). Wrong keys fail closed.
- Inventory lives in the **config dir** as `hosts.toml` (never in the repo).
- `wardline hosts sudoers` prints a suggested allowlist; Wardline never edits remote sudoers.

## Setup

```bash
cp hosts.example.toml ~/.config/wardline/hosts.toml
# edit names, hosts, users, identity_file paths
wardline hosts list
wardline hosts accept-key lab01   # confirm fingerprint
wardline hosts test lab01
wardline scan --backend ssh --host lab01 --profile quick
wardline scan --backend ssh --all-hosts --profile standard
```

Paths:

- `hosts.toml` → `wardline hosts path`
- `known_hosts` → same config directory (`0600`)

## Fleet

`--all-hosts` runs a concurrency-limited fleet scan (default `fleet_concurrency = 4`
in `hosts.toml`). Each host’s report is saved under that hostname in the Vault.

## TUI

Press `h` for the Hosts screen (test connection, accept key, fleet posture overview).
The dashboard also shows a per-host fleet summary from the Vault.
