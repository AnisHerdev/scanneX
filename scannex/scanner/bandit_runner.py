"""Bandit static security analyzer integration."""

import json
import subprocess
import sys
import tempfile
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


# Mapping of Bandit test IDs to standard CWEs and vulnerability types
BANDIT_VULN_MAP = {
    "B608": ("SQL_INJECTION", "CWE-89", CanaryType.REFLECTED),
    "B602": ("COMMAND_INJECTION", "CWE-78", CanaryType.FILE_MARKER),
    "B605": ("COMMAND_INJECTION", "CWE-78", CanaryType.FILE_MARKER),
    "B607": ("COMMAND_INJECTION", "CWE-78", CanaryType.FILE_MARKER),
    "B301": ("INSECURE_DESERIALIZATION", "CWE-502", CanaryType.FILE_MARKER),
    "B302": ("INSECURE_DESERIALIZATION", "CWE-502", CanaryType.FILE_MARKER),
    "B303": ("INSECURE_HASH", "CWE-327", CanaryType.REFLECTED),
    "B701": ("SSTI", "CWE-94", CanaryType.REFLECTED),
    "B702": ("XSS", "CWE-79", CanaryType.REFLECTED),
}


class BanditRunner:
    """Executes Bandit static analysis and outputs structured findings."""

    def __init__(self, target_dir: Path | str):
        self.target_dir = Path(target_dir).resolve()
        self.route_mapper = RouteMapper(self.target_dir)

    def run(self) -> list[Finding]:
        """Run Bandit on the target directory and return findings."""
        if not self.target_dir.exists():
            return []

        # Run bandit via python -m bandit to avoid blocked .exe policies
        cmd = [
            sys.executable,
            "-m",
            "bandit",
            "-r",
            str(self.target_dir),
            "-f",
            "json",
            "-q",
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30,
            )
            # Bandit returns exit code 1 if issues are found, which is expected
            raw_json = result.stdout.strip()
            if not raw_json:
                return []
            data = json.loads(raw_json)
        except Exception:
            return []

        findings: list[Finding] = []
        for result_item in data.get("results", []):
            finding = self._parse_bandit_item(result_item)
            if finding:
                findings.append(finding)

        return findings

    def _parse_bandit_item(self, item: dict) -> Optional[Finding]:
        """Convert a Bandit JSON result item into a ScanneX Finding."""
        filename = item.get("filename", "")
        line_number = item.get("line_number", 1)
        test_id = item.get("test_id", "")
        issue_text = item.get("issue_text", "Static vulnerability identified")
        issue_severity = item.get("issue_severity", "MEDIUM").upper()
        code_sink = item.get("code", "").strip()

        # Vulnerability type and CWE resolution
        vuln_type, cwe, default_canary = BANDIT_VULN_MAP.get(
            test_id, ("INSECURE_CODE", "CWE-699", CanaryType.REFLECTED)
        )

        severity_map = {
            "HIGH": Severity.HIGH,
            "MEDIUM": Severity.MEDIUM,
            "LOW": Severity.LOW,
        }
        severity = severity_map.get(issue_severity, Severity.MEDIUM)

        # Relativize path if possible
        try:
            rel_path = str(Path(filename).relative_to(self.target_dir))
        except ValueError:
            rel_path = filename

        finding = Finding(
            file_path=rel_path,
            line_number=line_number,
            vuln_type=vuln_type,
            cwe=cwe,
            severity=severity,
            title=f"[{test_id}] {issue_text}",
            description=f"Bandit rule {test_id} flagged: {issue_text}",
            sink_code=code_sink,
            source="static_bandit",
            status=FindingStatus.CONFIRMED_STATIC,
        )
        finding.add_trace(f"Identified by Bandit rule {test_id} at line {line_number}")

        # Attach route context and synthesize probe specification
        route = self.route_mapper.find_route_for_line(filename, line_number)
        if route:
            canary_token = f"SCANX_CANARY_{uuid.uuid4().hex[:8].upper()}"
            probe_spec = self._synthesize_probe_spec(route, vuln_type, default_canary, canary_token)
            finding.probe_spec = probe_spec
            finding.add_trace(f"Mapped to HTTP endpoint {probe_spec.method} {probe_spec.endpoint}")

        return finding

    def _synthesize_probe_spec(
        self,
        route,
        vuln_type: str,
        canary_type: CanaryType,
        canary_token: str,
    ) -> ProbeSpec:
        """Synthesize an actionable canary probe based on the enclosing route."""
        endpoint = route.endpoint
        method = route.methods[0] if route.methods else "GET"
        
        # Determine primary target parameter
        param_name = route.param_names[0] if route.param_names else "input"
        param_source = route.param_sources.get(param_name, "param")

        params: dict = {}
        data: dict = {}
        file_marker_path = None

        if vuln_type == "SQL_INJECTION":
            # Benign canary injection (UNION SELECT or error reflection)
            payload = f"' UNION SELECT 1, '{canary_token}', 'admin'--"
            if method == "POST" or param_source == "data":
                data[param_name] = payload
            else:
                params[param_name] = payload

        elif vuln_type == "COMMAND_INJECTION":
            # Harmless cross-platform file marker creation
            temp_dir = Path(tempfile.gettempdir())
            marker_name = f"{canary_token.lower()}.txt"
            file_marker_path = str(temp_dir / marker_name)
            payload = f"127.0.0.1 & echo canary > {file_marker_path}"
            if method == "POST" or param_source == "data":
                data[param_name] = payload
            else:
                params[param_name] = payload

        elif vuln_type == "SSTI":
            # Dynamic template expression evaluation (1337 * 7331 = 9799547)
            canary_token = "9799547"
            payload = "{{ 1337 * 7331 }}"
            if method == "POST" or param_source == "data":
                data[param_name] = payload
            else:
                params[param_name] = payload

        else:
            payload = canary_token
            if method == "POST":
                data[param_name] = payload
            else:
                params[param_name] = payload

        return ProbeSpec(
            endpoint=endpoint,
            method=method,
            params=params,
            data=data,
            canary_type=canary_type,
            canary_token=canary_token,
            file_marker_path=file_marker_path,
        )
