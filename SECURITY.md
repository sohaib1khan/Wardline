# Security Policy

## Supported versions

Wardline is pre-1.0. Security fixes are applied to the latest commit on the
default branch only.

## Reporting a vulnerability

Please **do not** open a public GitHub issue for security vulnerabilities.

Email a private report to the maintainers (or use GitHub Security Advisories
once enabled on the repository) with:

- A short description of the issue and its impact
- Steps to reproduce (PoC if available)
- Affected version / commit hash
- Whether you plan to disclose publicly and preferred timeline

We aim to acknowledge reports within 7 days.

## Design constraints relevant to security

- Wardline is a scanner orchestrator, not an antivirus/EDR.
- It never automatically remediates, deletes, or quarantines host files.
- Vault paths use `0700` directories and `0600` files.
- Remote mode uses key-based SSH only with strict host-key checking.
- Export supports `--redact` to mask IPs, hostnames, usernames, and home paths.
- Secrets (webhook URLs, keys) must never be committed; use env vars or a
  `0600` secrets file under the config directory.
