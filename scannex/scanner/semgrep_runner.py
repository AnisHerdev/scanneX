"""Semgrep static taint analysis integration with graceful fallback."""

import json
import re
import shutil
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


class SemgrepRunner:
    """Executes Semgrep taint rules on target repositories."""

    def __init__(self, target_dir: Path | str):
        self.target_dir = Path(target_dir).resolve()
        self.route_mapper = RouteMapper(self.target_dir)

    @classmethod
    def get_executable(cls) -> Optional[str]:
        """Find the semgrep executable on PATH or adjacent to sys.executable."""
        exe = shutil.which("semgrep")
        if exe:
            return exe
        py_dir = Path(sys.executable).parent
        exe = shutil.which("semgrep", path=str(py_dir))
        if exe:
            return exe
        for candidate in [py_dir / "semgrep.exe", py_dir / "semgrep"]:
            if candidate.exists():
                return str(candidate)
        return None

    def is_available(self) -> bool:
        """Check if Semgrep CLI is installed and accessible."""
        return self.get_executable() is not None

    def run(self) -> list[Finding]:
        """Run Semgrep scan using --config auto; return empty list if execution fails."""
        semgrep_bin = self.get_executable()
        if not semgrep_bin or not self.target_dir.exists():
            print("Execution Failure")
            return []

        # Note: --metrics=off must NOT be passed with --config auto as Semgrep requires
        # metrics to resolve the auto configuration fingerprint from its registry.
        cmd = [
            semgrep_bin,
            "scan",
            "--config",
            "auto",
            "--disable-version-check",
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
                print("Execution Failure")
                return []
            data = json.loads(raw_json)
        except Exception:
            print("Execution Failure")
            return []

        findings: list[Finding] = []
        for result_item in data.get("results", []):
            finding = self._parse_semgrep_item(result_item)
            if finding:
                findings.append(finding)

        return findings

    def _resolve_vulnerability_metadata(self, check_id: str, extra: dict) -> tuple[str, str, CanaryType]:
        """Dynamically extract CWE, vulnerability type, and canary probe type from Semgrep metadata."""
        metadata = extra.get("metadata", {})

        # 1. Resolve CWE identifier
        cwe = "CWE-699"
        raw_cwe = metadata.get("cwe")
        if isinstance(raw_cwe, list) and raw_cwe:
            raw_cwe = str(raw_cwe[0])
        elif isinstance(raw_cwe, str):
            raw_cwe = raw_cwe.strip()
        else:
            raw_cwe = ""

        if raw_cwe:
            cwe_match = re.search(r"CWE-\d+", raw_cwe, re.IGNORECASE)
            if cwe_match:
                cwe = cwe_match.group(0).upper()
            else:
                cwe = raw_cwe.split(":")[0].strip()

        # 2. Extract classification signals
        vuln_class = metadata.get("vulnerability_class")
        if isinstance(vuln_class, list) and vuln_class:
            vuln_class_str = " ".join(str(v) for v in vuln_class).lower()
        elif isinstance(vuln_class, str):
            vuln_class_str = vuln_class.lower()
        else:
            vuln_class_str = ""

        combined_signals = f"{check_id} {vuln_class_str} {cwe} {extra.get('message', '')}".lower()

        # 3. Classify into standard ScanneX vulnerability categories
        if "sql" in combined_signals or cwe == "CWE-89":
            return "SQL_INJECTION", (cwe if cwe != "CWE-699" else "CWE-89"), CanaryType.REFLECTED

        if any(k in combined_signals for k in ["command", "os.system", "subprocess", "shell", "exec", "system("]) or cwe in ("CWE-78", "CWE-88"):
            return "COMMAND_INJECTION", (cwe if cwe != "CWE-699" else "CWE-78"), CanaryType.FILE_MARKER

        if any(k in combined_signals for k in ["template", "ssti", "render_template_string"]) or cwe in ("CWE-94", "CWE-96", "CWE-1336"):
            return "SSTI", (cwe if cwe != "CWE-699" else "CWE-94"), CanaryType.REFLECTED

        if "xss" in combined_signals or "cross-site scripting" in combined_signals or cwe == "CWE-79":
            return "XSS", (cwe if cwe != "CWE-699" else "CWE-79"), CanaryType.REFLECTED

        if any(k in combined_signals for k in ["traversal", "file inclusion", "lfi", "rfi", "path-traversal"]) or cwe in ("CWE-22", "CWE-23", "CWE-98"):
            return "PATH_TRAVERSAL", (cwe if cwe != "CWE-699" else "CWE-22"), CanaryType.REFLECTED

        if any(k in combined_signals for k in ["deserialization", "pickle", "yaml.load", "unserialize"]) or cwe == "CWE-502":
            return "INSECURE_DESERIALIZATION", (cwe if cwe != "CWE-699" else "CWE-502"), CanaryType.FILE_MARKER

        if any(k in combined_signals for k in ["ssrf", "server-side request"]) or cwe == "CWE-918":
            return "SSRF", (cwe if cwe != "CWE-699" else "CWE-918"), CanaryType.REFLECTED

        if any(k in combined_signals for k in ["auth", "jwt", "login", "session", "bypass"]) or cwe in ("CWE-287", "CWE-306"):
            return "AUTH_BYPASS", (cwe if cwe != "CWE-699" else "CWE-287"), CanaryType.REFLECTED

        if "idor" in combined_signals or cwe == "CWE-639":
            return "IDOR", (cwe if cwe != "CWE-699" else "CWE-639"), CanaryType.REFLECTED

        if any(k in combined_signals for k in ["hash", "md5", "sha1", "crypto", "cipher"]) or cwe in ("CWE-327", "CWE-328"):
            return "INSECURE_HASH", (cwe if cwe != "CWE-699" else "CWE-327"), CanaryType.REFLECTED

        # If Semgrep provided an explicit vulnerability_class, derive an uppercase token
        if vuln_class_str:
            clean_class = re.sub(r"[^A-Za-z0-9]+", "_", vuln_class_str.strip()).upper().strip("_")
            if clean_class:
                return clean_class, cwe, CanaryType.REFLECTED

        return "TAINT_SINK", cwe, CanaryType.REFLECTED

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

        # Fallback to reading the actual source file line if code_sink is empty or 'requires login'
        if not code_sink or code_sink.lower() == "requires login":
            try:
                target_file = Path(path_str)
                if not target_file.is_absolute():
                    target_file = (self.target_dir / target_file).resolve()
                if target_file.is_file():
                    file_lines = target_file.read_text(encoding="utf-8", errors="ignore").splitlines()
                    if 1 <= line_number <= len(file_lines):
                        code_sink = file_lines[line_number - 1].strip()
            except Exception:
                pass

        severity_map = {
            "ERROR": Severity.HIGH,
            "WARNING": Severity.MEDIUM,
            "INFO": Severity.LOW,
        }
        severity = severity_map.get(severity_str, Severity.MEDIUM)

        # Dynamically resolve vulnerability type, CWE, and canary probe type
        vuln_type, cwe, canary_type = self._resolve_vulnerability_metadata(check_id, extra)

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
            method = route.methods[0] if route.methods else "GET"
            target_param = route.param_names[0] if route.param_names else "input"
            param_source = route.param_sources.get(target_param, "param")

            params: dict = {}
            data: dict = {}
            file_marker_path = None

            if canary_type == CanaryType.FILE_MARKER:
                temp_dir = Path(tempfile.gettempdir())
                file_marker_path = str(temp_dir / f"{canary_token.lower()}.txt")
                payload = f"127.0.0.1 & echo canary > {file_marker_path}"
            elif vuln_type == "SQL_INJECTION":
                payload = f"' UNION SELECT 1, '{canary_token}', 'admin'--"
            elif vuln_type == "SSTI":
                payload = "{{ 1337 * 7331 }}"
                canary_token = "9799547"
            else:
                payload = canary_token

            if method == "POST" or param_source == "data":
                data[target_param] = payload
            else:
                params[target_param] = payload

            probe_spec = ProbeSpec(
                endpoint=route.endpoint,
                method=method,
                params=params,
                data=data,
                canary_type=canary_type,
                canary_token=canary_token,
                file_marker_path=file_marker_path,
            )
            finding.probe_spec = probe_spec
            finding.add_trace(f"Mapped to HTTP endpoint {probe_spec.method} {probe_spec.endpoint}")

        return finding
