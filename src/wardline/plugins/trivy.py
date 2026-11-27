"""Trivy rootfs vulnerability scanner."""

from __future__ import annotations

import json
import re
from typing import Any

from wardline.backends.base import Backend
from wardline.core.distro import DistroInfo
from wardline.core.models import Category, Finding, PluginStatus, Severity
from wardline.plugins.base import DetectResult, ParseResult, Plugin, default_capabilities

# Compromised releases (Trivy March 2026 supply-chain incident).
TRIVY_DENYLIST = frozenset({"0.69.4", "0.69.5", "0.69.6"})

_VERSION_RE = re.compile(r"(?im)^Version:\s*(\S+)")
_SEVERITY_MAP = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "UNKNOWN": Severity.INFO,
}


class TrivyPlugin(Plugin):
    name = "trivy"
    display_name = "Trivy rootfs"
    category = Category.VULNERABILITY
    description = "Aqua Trivy filesystem/rootfs vulnerability scan."
    needs_root = False
    needs_network = True
    default_timeout = 900.0
    version_denylist = TRIVY_DENYLIST
    capabilities = default_capabilities()

    async def detect(self, backend: Backend) -> DetectResult:
        path = await backend.which("trivy")
        if not path:
            return DetectResult(installed=False)

        result = await backend.run(["trivy", "--version"], timeout=30.0)
        text = f"{result.stdout}\n{result.stderr}"
        match = _VERSION_RE.search(text)
        version = match.group(1) if match else None
        # Normalize v-prefix if present.
        if version and version.startswith("v"):
            version = version[1:]

        reason = self.check_denylist(version)
        if reason:
            return DetectResult(
                installed=True,
                version=version,
                path=path,
                denylisted=True,
                denylist_reason=(
                    f"compromised Trivy release {version} detected — "
                    "do not use; rotate credentials and install a safe version"
                ),
            )
        return DetectResult(installed=True, version=version, path=path)

    def install_hint(self, distro: DistroInfo) -> list[str]:
        if distro.is_debian_family:
            return [
                "# Install Trivy from Aqua's apt repo (pin a safe version; never 0.69.4-0.69.6):",
                "sudo apt install -y wget apt-transport-https gnupg",
                "wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key "
                "| gpg --dearmor | sudo tee /usr/share/keyrings/trivy.gpg > /dev/null",
                'echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] '
                'https://aquasecurity.github.io/trivy-repo/deb generic main" '
                "| sudo tee /etc/apt/sources.list.d/trivy.list",
                "sudo apt update && sudo apt install -y trivy",
            ]
        if distro.is_rhel_family:
            return [
                "# Install Trivy from Aqua's yum repo (pin a safe version; never 0.69.4-0.69.6):",
                "sudo tee /etc/yum.repos.d/trivy.repo <<'EOF'",
                "[trivy]",
                "name=Trivy repository",
                "baseurl=https://aquasecurity.github.io/trivy-repo/rpm/releases/$basearch/",
                "gpgcheck=1",
                "enabled=1",
                "gpgkey=https://aquasecurity.github.io/trivy-repo/rpm/public.key",
                "EOF",
                "sudo dnf install -y trivy",
            ]
        return [
            "# See https://trivy.dev for install options. Never install 0.69.4, 0.69.5, or 0.69.6."
        ]

    def build_commands(
        self, backend: Backend, options: dict[str, Any] | None = None
    ) -> list[list[str]]:
        options = options or {}
        root = backend.path(str(options.get("rootfs", "/")))
        return [
            [
                "trivy",
                "rootfs",
                "--scanners",
                "vuln",
                "--severity",
                "HIGH,CRITICAL",
                "--ignore-unfixed",
                "--format",
                "json",
                root,
            ]
        ]

    def interpret_exit_code(self, code: int) -> PluginStatus:
        return PluginStatus.OK if code == 0 else PluginStatus.FAILED

    def denylist_findings(self, *, scan_id: str, host: str, version: str | None) -> list[Finding]:
        ver = version or "unknown"
        return [
            Finding(
                scan_id=scan_id,
                host=host,
                plugin=self.name,
                rule_id="TRIVY-DENYLIST",
                category=Category.VULNERABILITY,
                severity=Severity.CRITICAL,
                title="Compromised Trivy release detected — rotate credentials",
                description=(
                    f"Trivy {ver} is on the Wardline denylist "
                    f"({', '.join(sorted(TRIVY_DENYLIST))}) due to a supply-chain incident."
                ),
                location=f"trivy@{ver}",
                fix_hint=(
                    "Remove this Trivy binary, rotate any credentials used with it, "
                    "and install a different pinned safe version."
                ),
            )
        ]

    def parse(
        self,
        raw_output: str,
        exit_code: int,
        *,
        scan_id: str,
        host: str,
        options: dict[str, Any] | None = None,
    ) -> ParseResult:
        del options
        findings: list[Finding] = []

        if "TOOMANYREQUESTS" in raw_output:
            findings.append(
                Finding(
                    scan_id=scan_id,
                    host=host,
                    plugin=self.name,
                    rule_id="TRIVY-TOOMANYREQUESTS",
                    category=Category.VULNERABILITY,
                    severity=Severity.MEDIUM,
                    title="Trivy vulnerability DB rate-limited (TOOMANYREQUESTS)",
                    description="Trivy could not refresh its DB due to registry rate limits.",
                    location="trivy-db",
                    evidence="TOOMANYREQUESTS",
                    fix_hint=(
                        "Upgrade Trivy, run `trivy --download-db-only` once, "
                        "then use `--skip-db-update` for subsequent scans."
                    ),
                )
            )

        payload = _extract_json(raw_output)
        if payload is None:
            if findings:
                return ParseResult(findings=findings)
            if exit_code != 0:
                return ParseResult(
                    findings=[
                        Finding(
                            scan_id=scan_id,
                            host=host,
                            plugin=self.name,
                            rule_id="TRIVY-PARSE-ERROR",
                            category=Category.VULNERABILITY,
                            severity=Severity.MEDIUM,
                            title="Trivy produced no parseable JSON output",
                            description="Could not parse Trivy JSON; see raw output.",
                            location="trivy",
                            evidence=raw_output[:500],
                        )
                    ]
                )
            return ParseResult(findings=findings)

        for result in payload.get("Results") or []:
            target = str(result.get("Target") or "rootfs")
            for vuln in result.get("Vulnerabilities") or []:
                cve = str(vuln.get("VulnerabilityID") or "UNKNOWN")
                pkg = str(vuln.get("PkgName") or "unknown")
                installed = str(vuln.get("InstalledVersion") or "")
                severity = _SEVERITY_MAP.get(
                    str(vuln.get("Severity") or "UNKNOWN").upper(),
                    Severity.INFO,
                )
                title = str(vuln.get("Title") or cve)
                refs = []
                if vuln.get("PrimaryURL"):
                    refs.append(str(vuln["PrimaryURL"]))
                refs.extend(str(r) for r in (vuln.get("References") or [])[:5])
                findings.append(
                    Finding(
                        scan_id=scan_id,
                        host=host,
                        plugin=self.name,
                        rule_id=cve,
                        category=Category.VULNERABILITY,
                        severity=severity,
                        title=title,
                        description=str(vuln.get("Description") or ""),
                        location=f"{pkg}@{installed}" if installed else pkg,
                        evidence=f"{target}: {cve} in {pkg} {installed}",
                        cve_ids=[cve] if cve.startswith("CVE-") else [],
                        fix_hint=(
                            f"Upgrade {pkg} to {vuln.get('FixedVersion')}"
                            if vuln.get("FixedVersion")
                            else f"Review {cve} for {pkg}"
                        ),
                        references=refs,
                    )
                )

        return ParseResult(
            findings=findings, extras={"result_count": len(payload.get("Results") or [])}
        )


def _extract_json(raw: str) -> dict[str, Any] | None:
    text = raw.strip()
    if not text:
        return None
    # Prefer a full-document parse; fall back to first JSON object substring.
    try:
        data = json.loads(text)
        return data if isinstance(data, dict) else None
    except json.JSONDecodeError:
        start = text.find("{")
        end = text.rfind("}")
        if start < 0 or end <= start:
            return None
        try:
            data = json.loads(text[start : end + 1])
            return data if isinstance(data, dict) else None
        except json.JSONDecodeError:
            return None
