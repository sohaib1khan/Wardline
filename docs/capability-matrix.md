# Capability matrix

Generated from plugin metadata (`wardline.plugins`). Re-run:

```bash
uv run wardline docker matrix
```

Levels: **full** · **partial** (see note) · **unavailable**.

| Plugin | Local | Docker | SSH |
|---|---|---|---|
| AIDE | full | partial — root_prefix / verify | full |
| chkrootkit | full | partial — chkrootkit -r /host (verify) | full |
| ClamAV | full | full | full |
| Lynis | full | partial — verify Lynis rootdir /host support | full |
| Nmap | full | full | full |
| OpenSCAP / USG | full | partial — oscap-chroot verify | full |
| Package verify | full | full | full |
| Patch status | full | partial | full |
| Persistence | full | full | full |
| rkhunter | full | partial — verify usefulness in container | full |
| ss baseline | full | full | full |
| Trivy rootfs | full | full | full |
