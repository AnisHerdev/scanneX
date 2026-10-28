"""Semgrep static taint analysis integration with graceful fallback."""

import json
import shutil
import subprocess
import uuid
from pathlib import Path
from typing import Optional

from scannex.db.models import (
    CanaryType,
    Finding,
    FindingStatus,
    ProbeSpec,
    Severity,
)
from scannex.scanner.route_mapper import RouteMapper


class SemgrepRunner:
    """Executes Semgrep taint rules on target repositories."""

    def __init__(self, target_dir: Path | str):
        self.target_dir = Path(target_dir).resolve()
        self.route_mapper = RouteMapper(self.target_dir)

    def is_available(self) -> bool:
        """Check if Semgrep CLI is installed in PATH."""
        return shutil.which("semgrep") is not None

    def run(self) -> list[Finding]:
        """Run Semgrep scan if available; return empty list if not installed."""
        if not self.is_available() or not self.target_dir.exists():
            return []

        cmd = [
            "semgrep",
            "scan",
            "--config",
            "p/security-audit",
            "--json",
            "-q",
            str(self.target_dir),
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=45,
            )
            raw_json = result.stdout.strip()
            if not raw_json:
                return []
            data = json.loads(raw_json)
        except Exception:
            return []

        findings: list[Finding] = []
        for result_item in data.get("results", []):
            finding = self._parse_semgrep_item(result_item)
            if finding:
                findings.append(finding)

        return findings

    def _parse_semgrep_item(self, item: dict) -> Optional[Finding]:
        """Convert a Semgrep JSON finding into a ScanneX Finding."""
        path_str = item.get("path", "")
        start = item.get("start", {})
        line_number = start.get("line", 1)
        check_id = item.get("check_id", "semgrep.rule")
        extra = item.get("extra", {})
        message = extra.get("message", "Semgrep security finding")
        severity_str = extra.get("severity", "WARNING").upper()
        code_sink = extra.get("lines", "").strip()

        severity_map = {
            "ERROR": Severity.HIGH,
            "WARNING": Severity.MEDIUM,
            "INFO": Severity.LOW,
        }
        severity = severity_map.get(severity_str, Severity.MEDIUM)

        # Identify vulnerability type from check_id
        vuln_type = "TAINT_SINK"
        cwe = "CWE-699"
        canary_type = CanaryType.REFLECTED

        check_lower = check_id.lower()
        if "sql" in check_lower:
            vuln_type = "SQL_INJECTION"
            cwe = "CWE-89"
        elif "command" in check_lower or "exec" in check_lower:
            vuln_type = "COMMAND_INJECTION"
            cwe = "CWE-78"
            canary_type = CanaryType.FILE_MARKER
        elif "template" in check_lower or "ssti" in check_lower:
            vuln_type = "SSTI"
            cwe = "CWE-94"
        elif "xss" in check_lower:
            vuln_type = "XSS"
            cwe = "CWE-79"

        try:
            rel_path = str(Path(path_str).relative_to(self.target_dir))
        except ValueError:
            rel_path = path_str

        finding = Finding(
            file_path=rel_path,
            line_number=line_number,
            vuln_type=vuln_type,
            cwe=cwe,
            severity=severity,
            title=f"[{check_id}] {message.splitlines()[0] if message else check_id}",
            description=message,
            sink_code=code_sink,
            source="static_semgrep",
            status=FindingStatus.CONFIRMED_STATIC,
        )
        finding.add_trace(f"Identified by Semgrep rule {check_id} at line {line_number}")

        # Attach route context and synthesize probe specification
        route = self.route_mapper.find_route_for_line(path_str, line_number)
        if route:
            canary_token = f"SCANX_CANARY_{uuid.uuid4().hex[:8].upper()}"
            probe_spec = ProbeSpec(
                endpoint=route.endpoint,
                method=route.methods[0] if route.methods else "GET",
                params={route.param_names[0]: canary_token} if route.param_names else {"canary": canary_token},
                canary_type=canary_type,
                canary_token=canary_token,
            )
            finding.probe_spec = probe_spec
            finding.add_trace(f"Mapped to HTTP endpoint {probe_spec.method} {probe_spec.endpoint}")

        return finding
