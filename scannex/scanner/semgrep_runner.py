"""Semgrep static taint analysis integration supporting Docker and native CLI."""

import json
import logging
import os
import re
import shutil
import subprocess
import sys
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

logger = logging.getLogger(__name__)


class SemgrepRunner:
    """Executes Semgrep taint and SAST rules on target repositories."""

    DEFAULT_CONFIGS = ["p/owasp-top-ten", "p/security-audit", "p/php", "p/javascript"]

    def __init__(
        self,
        target_dir: Path | str,
        configs: Optional[list[str]] = None,
        scan_workflows: bool = False,
    ):
        self.target_dir = Path(target_dir).resolve()
        self.route_mapper = RouteMapper(self.target_dir)
        self.configs = configs if configs is not None else list(self.DEFAULT_CONFIGS)
        self.scan_workflows = scan_workflows

    def _is_docker_available(self) -> bool:
        """Check if Docker engine is running and accessible."""
        try:
            res = subprocess.run(["docker", "info"], capture_output=True, timeout=3)
            return res.returncode == 0
        except Exception:
            return False

    def _find_cli_binary(self) -> Optional[str]:
        """Find native semgrep or pysemgrep executable."""
        candidates = [
            shutil.which("semgrep"),
            shutil.which("pysemgrep"),
            str(Path(sys.prefix) / "Scripts" / "pysemgrep.exe"),
            str(Path(sys.prefix) / "Scripts" / "semgrep.exe"),
            str(Path(sys.prefix) / "bin" / "semgrep"),
            str(Path(sys.prefix) / "bin" / "pysemgrep"),
        ]
        for candidate in candidates:
            if candidate and Path(candidate).is_file():
                return candidate
        return None

    def is_available(self) -> bool:
        """Check if Semgrep can be executed via Docker or native CLI."""
        return self._is_docker_available() or (self._find_cli_binary() is not None)

    def run(self) -> list[Finding]:
        """Run Semgrep scan and return structured findings."""
        if not self.target_dir.exists():
            return []

        use_docker = self._is_docker_available()
        cli_bin = self._find_cli_binary()

        if not use_docker and not cli_bin:
            logger.warning("Semgrep is not available via Docker or native CLI; skipping scan.")
            return []

        # If no configs selected, skip Semgrep execution
        active_configs = [c for c in self.configs if c]
        if self.scan_workflows and "p/github-actions" not in active_configs:
            active_configs = list(active_configs) + ["p/github-actions"]
        if not active_configs:
            return []

        config_args: list[str] = []
        for c in active_configs:
            config_args.extend(["--config", c])

        exclude_args: list[str] = []
        if not self.scan_workflows:
            exclude_args.extend(["--exclude", ".github"])

        if "p/javascript" not in active_configs:
            for pat in ("*.js", "*.jsx", "*.ts", "*.tsx", "*.mjs", "*.cjs"):
                exclude_args.extend(["--exclude", pat])

        if "p/php" not in active_configs:
            for pat in ("*.php", "*.phtml"):
                exclude_args.extend(["--exclude", pat])

        if use_docker:
            # Mount target directory into container at /src
            target_str = str(self.target_dir)
            cmd = [
                "docker",
                "run",
                "--rm",
                "-v",
                f"{target_str}:/src",
                "semgrep/semgrep",
                "semgrep",
                "scan",
            ] + config_args + exclude_args + [
                "--json",
                "-q",
                "/src",
            ]
        else:
            cmd = [
                cli_bin,
                "scan",
            ] + config_args + exclude_args + [
                "--json",
                "-q",
                str(self.target_dir),
            ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120,
            )
            raw_stdout = result.stdout.strip()
            if not raw_stdout:
                if result.stderr:
                    logger.warning(f"Semgrep returned empty stdout, stderr: {result.stderr[:300]}")
                return []

            # Extract JSON object with fence/brace resilience
            data = None
            if raw_stdout.startswith("{") and raw_stdout.endswith("}"):
                try:
                    data = json.loads(raw_stdout)
                except Exception:
                    pass

            if not data:
                start = raw_stdout.find("{")
                end = raw_stdout.rfind("}")
                if start != -1 and end > start:
                    try:
                        data = json.loads(raw_stdout[start : end + 1])
                    except Exception:
                        pass

            if not data or not isinstance(data, dict):
                return []

        except subprocess.TimeoutExpired:
            logger.error("Semgrep scan timed out after 120 seconds.")
            return []
        except Exception as e:
            logger.error(f"Semgrep execution error: {e}")
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
        end = item.get("end", {})
        line_number = int(start.get("line", 1))
        end_line = int(end.get("line", line_number))
        check_id = item.get("check_id", "semgrep.rule")
        extra = item.get("extra", {})
        message = extra.get("message", "Semgrep security finding")
        severity_str = extra.get("severity", "WARNING").upper()

        # Handle container mount paths (/src/...)
        rel_path = path_str
        if rel_path.startswith("/src/"):
            rel_path = rel_path[5:]
        elif rel_path == "/src":
            rel_path = ""
        else:
            try:
                rel_path = str(Path(path_str).relative_to(self.target_dir))
            except ValueError:
                rel_path = path_str.replace("\\", "/").lstrip("/")

        # Suppress findings if the corresponding language rule pack has been deselected
        active_configs = [c for c in self.configs if c]
        if "p/javascript" not in active_configs:
            js_exts = (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs")
            if rel_path.lower().endswith(js_exts) or check_id.lower().startswith(("javascript.", "typescript.", "js.", "ts.")):
                return None

        if "p/php" not in active_configs:
            php_exts = (".php", ".phtml")
            if rel_path.lower().endswith(php_exts) or check_id.lower().startswith(("php.", "php-")):
                return None

        # Extract authentic code sink directly from disk if available
        code_sink = ""
        local_file = self.target_dir / rel_path
        if local_file.is_file():
            try:
                file_lines = local_file.read_text(encoding="utf-8", errors="ignore").splitlines()
                start_idx = max(0, line_number - 1)
                end_idx = min(len(file_lines), max(end_line, line_number))
                code_sink = "\n".join(file_lines[start_idx:end_idx]).strip()
            except Exception:
                pass

        if not code_sink:
            semgrep_lines = extra.get("lines", "").strip()
            if semgrep_lines and semgrep_lines != "requires login":
                code_sink = semgrep_lines

        severity_map = {
            "ERROR": Severity.HIGH,
            "WARNING": Severity.MEDIUM,
            "INFO": Severity.LOW,
        }
        severity = severity_map.get(severity_str, Severity.MEDIUM)

        # Extract vulnerability type and CWE from rule metadata if present
        metadata = extra.get("metadata", {}) or {}
        raw_cwes = metadata.get("cwe", [])
        if isinstance(raw_cwes, str):
            raw_cwes = [raw_cwes]

        vuln_class = ""
        raw_classes = metadata.get("vulnerability_class", [])
        if isinstance(raw_classes, list) and raw_classes:
            vuln_class = str(raw_classes[0]).lower()
        elif isinstance(raw_classes, str):
            vuln_class = raw_classes.lower()

        cwe = "CWE-699"
        if raw_cwes:
            first_cwe = raw_cwes[0]
            # Match e.g. "CWE-89" from "CWE-89: Improper Neutralization..."
            match = re.search(r"CWE-\d+", first_cwe, re.IGNORECASE)
            if match:
                cwe = match.group(0).upper()

        vuln_type = "TAINT_SINK"
        canary_type = CanaryType.REFLECTED

        check_lower = check_id.lower()
        full_context = f"{check_lower} {vuln_class} {cwe.lower()} {message.lower()}"

        if "sql" in full_context or cwe == "CWE-89":
            vuln_type = "SQL_INJECTION"
            cwe = "CWE-89"
            canary_type = CanaryType.REFLECTED
        elif "command" in full_context or "exec" in full_context or "shell" in full_context or cwe == "CWE-78":
            vuln_type = "COMMAND_INJECTION"
            cwe = "CWE-78"
            canary_type = CanaryType.FILE_MARKER
        elif "template" in full_context or "ssti" in full_context or cwe in ("CWE-94", "CWE-96"):
            vuln_type = "SSTI"
            cwe = "CWE-94"
            canary_type = CanaryType.REFLECTED
        elif "traversal" in full_context or "lfi" in full_context or "rfi" in full_context or "filename" in full_context or cwe in ("CWE-22", "CWE-98"):
            vuln_type = "PATH_TRAVERSAL"
            cwe = "CWE-22"
            canary_type = CanaryType.REFLECTED
        elif "xss" in full_context or "cross-site scripting" in full_context or "echoed-request" in full_context or cwe == "CWE-79":
            vuln_type = "XSS"
            cwe = "CWE-79"
            canary_type = CanaryType.REFLECTED
        elif "phpinfo" in full_context or "info-leak" in full_context or cwe == "CWE-200":
            vuln_type = "INFO_DISCLOSURE"
            cwe = "CWE-200"
            canary_type = CanaryType.REFLECTED
        elif "csrf" in full_context or cwe == "CWE-352":
            vuln_type = "CSRF"
            cwe = "CWE-352"
            canary_type = CanaryType.REFLECTED
        elif "deserializ" in full_context or cwe == "CWE-502":
            vuln_type = "INSECURE_DESERIALIZATION"
            cwe = "CWE-502"
            canary_type = CanaryType.FILE_MARKER
        elif "github-action" in full_context or "mutable-action-tag" in full_context or "supply-chain" in full_context or cwe in ("CWE-1357", "CWE-1384"):
            vuln_type = "SUPPLY_CHAIN_RISK"
            cwe = "CWE-1357"
            canary_type = CanaryType.REFLECTED
        elif "crypto" in full_context or "hash" in full_context or cwe in ("CWE-327", "CWE-328"):
            vuln_type = "INSECURE_CRYPTO"
            cwe = "CWE-327"
            canary_type = CanaryType.REFLECTED
        elif "secret" in full_context or "credential" in full_context or "password" in full_context or cwe == "CWE-798":
            vuln_type = "HARDCODED_SECRET"
            cwe = "CWE-798"
            canary_type = CanaryType.REFLECTED
        elif "redirect" in full_context or cwe == "CWE-601":
            vuln_type = "OPEN_REDIRECT"
            cwe = "CWE-601"
            canary_type = CanaryType.REFLECTED
        elif "ssrf" in full_context or cwe == "CWE-918":
            vuln_type = "SSRF"
            cwe = "CWE-918"
            canary_type = CanaryType.REFLECTED

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

        # Attach route context and synthesize probe specification if route exists
        route = self.route_mapper.find_route_for_line(rel_path, line_number)
        if route:
            canary_token = f"SCANX_CANARY_{uuid.uuid4().hex[:8].upper()}"
            probe_spec = ProbeSpec(
                endpoint=route.endpoint,
                method=route.methods[0] if route.methods else "GET",
                params=({route.param_names[0]: (f"; touch /tmp/canary_{canary_token}.txt &" if canary_type == CanaryType.FILE_MARKER else canary_token)} if route.param_names else {"canary": (f"; touch /tmp/canary_{canary_token}.txt &" if canary_type == CanaryType.FILE_MARKER else canary_token)}),
                canary_type=canary_type,
                canary_token=canary_token,
                file_marker_path=(f"/tmp/canary_{canary_token}.txt" if canary_type == CanaryType.FILE_MARKER else None),
            )
            finding.probe_spec = probe_spec
            finding.add_trace(f"Mapped to HTTP endpoint {probe_spec.method} {probe_spec.endpoint}")

        return finding
