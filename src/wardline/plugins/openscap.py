"""OpenSCAP (RHEL family) / USG (Ubuntu) compliance plugin."""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from typing import Any

from wardline.backends.base import Backend
from wardline.core.distro import DistroInfo
from wardline.core.models import BackendKind, Category, Finding, PluginStatus, Severity
from wardline.plugins.base import (
    CapabilityLevel,
    DetectResult,
    ParseResult,
    Plugin,
    default_capabilities,
)

_XCCDF_NS = {"x": "http://checklists.nist.gov/xccdf/1.2"}
_SEV = {
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "unknown": Severity.MEDIUM,
}


class OpenScapPlugin(Plugin):
    name = "openscap"
    display_name = "OpenSCAP / USG"
    category = Category.COMPLIANCE
    description = "OpenSCAP XCCDF (RHEL family) or Ubuntu USG CIS audit."
    needs_root = True
    default_timeout = 1800.0
    capabilities = default_capabilities(
        docker=CapabilityLevel.PARTIAL,
        notes={BackendKind.DOCKER: "partial — oscap-chroot verify"},
    )

    async def detect(self, backend: Backend) -> DetectResult:
        oscap = await backend.which("oscap")
        usg = await backend.which("usg")
        if oscap:
            result = await backend.run(["oscap", "--version"], timeout=15.0)
            text = f"{result.stdout}\n{result.stderr}"
            match = re.search(r"oscap\s+tool.*?(\d+\.\d+\.\d+)", text, re.I | re.S)
            version = match.group(1) if match else "oscap"
            return DetectResult(installed=True, version=version, path=oscap, detail="oscap")
        if usg:
            return DetectResult(installed=True, version="usg", path=usg, detail="usg")
        return DetectResult(installed=False)

    def install_hint(self, distro: DistroInfo) -> list[str]:
        if distro.is_debian_family:
            return [
                "# Ubuntu USG requires Ubuntu Pro:",
                "sudo pro attach <token>",
                "sudo apt install -y usg",
            ]
        if distro.is_rhel_family:
            return [
                "sudo dnf install -y openscap-scanner scap-security-guide",
            ]
        return ["# install OpenSCAP / USG for your platform"]

    def build_commands(
        self, backend: Backend, options: dict[str, Any] | None = None
    ) -> list[list[str]]:
        options = options or {}
        mode = str(options.get("mode") or "auto")
        if mode == "usg" or options.get("prefer_usg"):
            return [["usg", "audit", "cis_level1_server"]]
        # Default oscap-style command; datastream path may be injected by options.
        ds = str(options.get("datastream") or "/usr/share/xml/scap/ssg/content/ssg-rhel9-ds.xml")
        profile = str(options.get("profile") or "xccdf_org.ssgproject.content_profile_cis")
        results = str(options.get("results") or "/tmp/wardline-oscap-results.xml")
        report = str(options.get("report") or "/tmp/wardline-oscap-report.html")
        del backend
        return [
            [
                "oscap",
                "xccdf",
                "eval",
                "--profile",
                profile,
                "--results",
                results,
                "--report",
                report,
                ds,
            ]
        ]

    def interpret_exit_code(self, code: int) -> PluginStatus:
        # Exit 2 means some rules failed — not a crash.
        if code in {0, 2}:
            return PluginStatus.OK
        return PluginStatus.FAILED

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
        if "ubuntu pro" in raw_output.lower() or "not attached" in raw_output.lower():
            findings.append(
                Finding(
                    scan_id=scan_id,
                    host=host,
                    plugin=self.name,
                    rule_id="USG-NO-PRO",
                    category=Category.COMPLIANCE,
                    severity=Severity.INFO,
                    title="Ubuntu USG requires Ubuntu Pro",
                    description="USG audit needs an attached Ubuntu Pro subscription.",
                    location="usg",
                    fix_hint="Attach Ubuntu Pro, then re-run the compliance profile.",
                )
            )

        xml_text = raw_output
        # Prefer explicit results XML if provided via options embedding.
        if options.get("results_xml"):
            xml_text = str(options["results_xml"])
        findings.extend(_parse_xccdf(xml_text, scan_id=scan_id, host=host, plugin=self.name))
        if exit_code not in {0, 2} and not findings:
            findings.append(
                Finding(
                    scan_id=scan_id,
                    host=host,
                    plugin=self.name,
                    rule_id="OSCAP-ERROR",
                    category=Category.COMPLIANCE,
                    severity=Severity.MEDIUM,
                    title="OpenSCAP/USG failed",
                    description=f"exit code {exit_code}",
                    location="openscap",
                    evidence=raw_output[:500],
                )
            )
        return ParseResult(findings=findings, extras={"exit_code": exit_code})


def _parse_xccdf(text: str, *, scan_id: str, host: str, plugin: str) -> list[Finding]:
    findings: list[Finding] = []
    if "<rule-result" not in text and "rule-result" not in text:
        return findings
    # Strip default namespace for simpler parsing if needed.
    cleaned = re.sub(r'\sxmlns="[^"]+"', "", text, count=1)
    try:
        root = ET.fromstring(cleaned)
    except ET.ParseError:
        return findings

    for rr in root.findall(".//rule-result"):
        result_el = rr.find("result")
        if result_el is None or (result_el.text or "").strip() != "fail":
            continue
        rule_id = rr.get("idref") or "unknown-rule"
        sev = _SEV.get((rr.get("severity") or "medium").lower(), Severity.MEDIUM)
        short = rule_id.rsplit("_rule_", 1)[-1]
        findings.append(
            Finding(
                scan_id=scan_id,
                host=host,
                plugin=plugin,
                rule_id=rule_id,
                category=Category.COMPLIANCE,
                severity=sev,
                title=f"Failed compliance rule: {short}",
                description=f"OpenSCAP/XCCDF rule failed: {rule_id}",
                location=rule_id,
                evidence=rule_id,
                fix_hint="Remediate per the SCAP/USG guidance for this rule.",
            )
        )
    return findings
