# Writing a Wardline plugin

Stub — filled in during Phase 3+.

Each plugin lives under `src/wardline/plugins/` and provides:

- Metadata (`name`, `category`, `needs_root`, timeouts, capabilities, …)
- `detect(backend)` — installed? version? denylist?
- `install_hint(distro)` — exact install commands (shown, never auto-run)
- `build_commands(backend, options)` — argument lists only (no shell strings)
- `parse(raw_output, exit_code)` → `list[Finding]`
- `interpret_exit_code(code)` → ok / findings / error

Plugins talk only to the backend interface — never `subprocess` directly.
