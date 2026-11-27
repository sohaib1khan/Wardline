"""Nmap network scan with scope allowlist (Safety rule 6)."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import Any

from wardline.backends.base import Backend
from wardline.core.distro import DistroInfo
from wardline.core.models import Category, Finding, PluginStatus, Severity
from wardline.plugins.base import DetectResult, ParseResult, Plugin, default_capabilities


def _cvss_to_severity(cvss: float) -> Severity:
    if cvss >= 9.0:
        return Severity.CRITICAL
    if cvss >= 7.0:
        return Severity.HIGH
    if cvss >= 4.0:
        return Severity.MEDIUM
    if cvss > 0:
        return Severity.LOW
    return Severity.INFO


class NmapPlugin(Plugin):
    name = "nmap"
    display_name = "Nmap"
    category = Category.NETWORK
    description = "Nmap service/version scan with vulners script (allowlisted targets only)."
    needs_root = False  # SYN scans may need root/NET_RAW; connect scan works unprivileged
    needs_network = True
    default_timeout = 1800.0
    capabilities = default_capabilities()

    async def detect(self, backend: Backend) -> DetectResult:
        path = await backend.which("nmap")
        if not path:
            return DetectResult(installed=False)
        result = await backend.run(["nmap", "--version"], timeout=15.0)
        text = f"{result.stdout}\n{result.stderr}"
        version = None
        for line in text.splitlines():
            if line.lower().startswith("nmap version"):
                parts = line.split()
                if len(parts) >= 3:
                    version = parts[2]
                break
        return DetectResult(installed=True, version=version, path=path)

    def install_hint(self, distro: DistroInfo) -> list[str]:
        if distro.is_debian_family:
            return [
                "sudo apt update && sudo apt install -y nmap",
                "# For vulners: ensure nmap NSE vulners script is installed",
            ]
        if distro.is_rhel_family:
            return ["sudo dnf install -y nmap"]
        return ["# install nmap from your distro"]

    def build_commands(
        self, backend: Backend, options: dict[str, Any] | None = None
    ) -> list[list[str]]:
        del backend
        options = options if options is not None else {}
        allowed = list(options.get("allowed_targets") or ["127.0.0.1"])
        requested = list(options.get("targets") or allowed)
        confirmed = set(options.get("confirmed_targets") or [])
        allowed_set = set(allowed)
        safe: list[str] = []
        refused: list[str] = []
        for target in requested:
            if target in allowed_set or target in confirmed or target == "127.0.0.1":
                safe.append(target)
            else:
                refused.append(target)
        options["refused_targets"] = refused
        commands: list[list[str]] = []
        for target in safe:
            commands.append(
                [
                    "nmap",
                    "-sV",
                    "--script",
                    "vulners",
                    "-p-",
                    "--min-rate",
                    "1000",
                    "-oX",
                    "-",
                    target,
                ]
            )
        return commands

    def interpret_exit_code(self, code: int) -> PluginStatus:
        return PluginStatus.OK if code == 0 else PluginStatus.FAILED

    def parse(
        self,
        raw_output: str,
        exit_code: int,
        *,
        scan_id: str,
        host: str,
        options: dict[str, Any] | None = None,
    ) -> ParseResult:
        options = options or {}
        findings: list[Finding] = []

        for target in options.get("refused_targets") or []:
            findings.append(
                Finding(
                    scan_id=scan_id,
                    host=host,
                    plugin=self.name,
                    rule_id="NMAP-SCOPE",
                    category=Category.NETWORK,
                    severity=Severity.MEDIUM,
                    title=f"Nmap target refused (not in allowlist): {target}",
                    description=(
                        "Safety rule 6: only scan.nmap.allowed_targets (+ 127.0.0.1) "
                        "may be scanned without per-run confirmation."
                    ),
                    location=target,
                    fix_hint="Add the target to scan.nmap.allowed_targets or confirm ownership.",
                )
            )

        if "vulners" in raw_output.lower() and (
            "no such script" in raw_output.lower() or "failed to open" in raw_output.lower()
        ):
            findings.append(
                Finding(
                    scan_id=scan_id,
                    host=host,
                    plugin=self.name,
                    rule_id="NMAP-VULNERS-MISSING",
                    category=Category.NETWORK,
                    severity=Severity.LOW,
                    title="Nmap vulners NSE script missing",
                    description="Nmap could not load the vulners script.",
                    location="nmap",
                    evidence="vulners script error",
                    fix_hint="Install/update the vulners NSE script for nmap.",
                )
            )

        xml_text = _extract_xml(raw_output)
        if xml_text:
            findings.extend(_parse_nmap_xml(xml_text, scan_id=scan_id, host=host, plugin=self.name))
        elif exit_code != 0 and not findings:
            findings.append(
                Finding(
                    scan_id=scan_id,
                    host=host,
                    plugin=self.name,
                    rule_id="NMAP-ERROR",
                    category=Category.NETWORK,
                    severity=Severity.MEDIUM,
                    title="Nmap failed",
                    description="No parseable XML output from nmap.",
                    location="nmap",
                    evidence=raw_output[:500],
                )
            )
        return ParseResult(findings=findings)


def _extract_xml(raw: str) -> str | None:
    start = raw.find("<?xml")
    if start < 0:
        start = raw.find("<nmaprun")
    if start < 0:
        return None
    end = raw.rfind("</nmaprun>")
    if end < 0:
        return None
    return raw[start : end + len("</nmaprun>")]


def _parse_nmap_xml(xml_text: str, *, scan_id: str, host: str, plugin: str) -> list[Finding]:
    findings: list[Finding] = []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return findings

    for host_el in root.findall("host"):
        addr_el = host_el.find("address")
        addr = addr_el.get("addr") if addr_el is not None else "unknown"
        ports = host_el.find("ports")
        if ports is None:
            continue
        for port_el in ports.findall("port"):
            state_el = port_el.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue
            proto = port_el.get("protocol", "tcp")
            portid = port_el.get("portid", "?")
            service_el = port_el.find("service")
            product = ""
            if service_el is not None:
                product = " ".join(
                    filter(
                        None,
                        [
                            service_el.get("name"),
                            service_el.get("product"),
                            service_el.get("version"),
                        ],
                    )
                )
            location = f"{addr}:{portid}/{proto}"
            findings.append(
                Finding(
                    scan_id=scan_id,
                    host=host,
                    plugin=plugin,
                    rule_id=f"NMAP-PORT-{portid}-{proto}",
                    category=Category.NETWORK,
                    severity=Severity.INFO,
                    title=f"Open port {portid}/{proto} on {addr}",
                    description=product or "open port",
                    location=location,
                    evidence=location,
                )
            )
            for script in port_el.findall("script"):
                if script.get("id") != "vulners":
                    continue
                for table in script.findall(".//table"):
                    elems = {e.get("key"): (e.text or "") for e in table.findall("elem")}
                    cve = elems.get("id") or ""
                    if not cve.startswith("CVE-"):
                        continue
                    try:
                        cvss = float(elems.get("cvss") or 0)
                    except ValueError:
                        cvss = 0.0
                    findings.append(
                        Finding(
                            scan_id=scan_id,
                            host=host,
                            plugin=plugin,
                            rule_id=cve,
                            category=Category.VULNERABILITY,
                            severity=_cvss_to_severity(cvss),
                            title=f"{cve} on {location}",
                            description=f"Nmap vulners reported {cve} (CVSS {cvss}).",
                            location=location,
                            evidence=script.get("output") or cve,
                            cve_ids=[cve],
                            fix_hint="Correlate with Trivy/distro advisories (rule R1).",
                        )
                    )
    return findings
