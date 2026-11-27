# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Phase 10: SSH backend (asyncssh, strict known_hosts, key auth),
  `wardline hosts` CLI (add/list/test/accept-key/sudoers), fleet scan with
  concurrency limit, Hosts TUI screen, and dashboard fleet overview.
- Phase 9: Docker scanner image (pinned base + checksummed Trivy),
  DockerBackend (`docker exec`, `/host` mapping, minimal caps),
  `wardline docker build|up|down|status|matrix`, generated capability matrix,
  and CI image build job.
- Phase 8: Findings explorer, Vault browser, diff view, typed soft-delete,
  Evidence Locker (opt-in copy-only), settings screen, and Guarded Baseline
  dialog; snapshot + pilot coverage for each flow.
- Phase 7: Correlation engine (rules R1–R7) with verdicts in reports;
  Guarded Baseline CLI (`wardline baseline aide|rkhunter`) that blocks on
  dirty package verification; rkhunter path extraction for R2.
- Phase 6: ClamAV, rkhunter, chkrootkit, AIDE, Nmap (scope allowlist),
  OpenSCAP/USG, pkg_verify, patch_status, and persistence plugins with
  sanitized fixtures/parser tests; quick profile includes patch_status.
- Phase 5: Textual TUI shell (theme, splash, dashboard, launcher, live scan),
  toasts/key hints/reduce-motion, bare `wardline` launches the TUI, live scans
  save to the Vault; snapshot + pilot tests for Phase 5 screens.
- Phase 4: Vault store + SQLite index, path-safety soft-delete to `.trash/`,
  JSON/Markdown/HTML reports with `--redact`, scan auto-save, and
  `wardline vault list|show|export|tag|delete|diff`.
- Phase 3: ss_baseline, Lynis, and Trivy plugins (parsers, install hints, Trivy
  denylist), sanitized fixtures, scan profiles, `wardline scan` CLI with summary
  output / `--json` / `--fail-on`.
- Phase 2: LocalBackend (async streaming, timeouts, nice/ionice), event bus,
  plugin base + registry + hidden dummy plugin, scan plugin runner, and a real
  `wardline doctor` host/plugin table.
- Phase 1 core: Pydantic Finding/Scan models, TOML config load/validation,
  XDG/root data paths with `0700`/`0600` permissions, logging setup, distro
  detection from `/etc/os-release`, and posture scoring.
- Phase 0 repository skeleton: packaging (`uv` + `src/` layout), CLI stub
  (`wardline --help` / `--version` / `doctor`), hygiene tooling (ruff, pyright,
  pytest, pre-commit, gitleaks), CI, Dependabot, and example configs.
