# Architecture

Stub — filled in as phases land.

Wardline is a Python package (`src/wardline`) that:

1. Discovers scanner **plugins** and runs them through interchangeable
   **backends** (local / Docker / SSH).
2. Normalizes every tool's output into a shared **Finding** model.
3. Runs a **correlation** engine over findings.
4. Persists results in a local **Vault** (SQLite index + per-scan directories).
5. Exposes the same engine via a **Textual TUI** and a **Typer CLI**.

See the project blueprint (local only; not in the repo) for the full design.
