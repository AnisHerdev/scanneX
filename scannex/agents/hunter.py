"""AI Hunter agent: discovers logic flaws, auth bypasses, and complex vulnerabilities."""

import ast
import json
import tempfile
import uuid
from pathlib import Path
from typing import Optional
from scannex.agents.base import BaseAgent
from scannex.db.models import (
    CanaryType,
    Finding,
    FindingStatus,
    ProbeSpec,
    Severity,
)
from scannex.scanner.route_mapper import RouteMapper


HUNTER_SYSTEM_PROMPT = """You are ScanneX AI Hunter, a world-class application security researcher.
Analyze the provided source code for logic bugs, authentication/authorization flaws, SSRF, IDOR, SSTI,
and dangerous input mishandling that standard static AST rules often miss.

Be concise. Limit your findings to at most 3 of the most critical vulnerabilities.
For each genuine vulnerability found, output a JSON array of findings matching this exact schema:
[
  {
    "file_path": "path/to/file.py",
    "line_number": 42,
    "vuln_type": "SSRF",
    "cwe": "CWE-918",
    "severity": "CRITICAL",
    "title": "Server-Side Request Forgery via unvalidated URL fetch",
    "description": "User-supplied target URL parameter is fetched via HTTP request without host validation.",
    "sink_code": "requests.get(target_url, timeout=5)",
    "endpoint": "/fetch",
    "method": "GET",
    "param_name": "url",
    "canary_type": "reflected"
  }
]

Allowed vuln_type values: SSTI, SQL_INJECTION, COMMAND_INJECTION, AUTH_BYPASS, IDOR, SSRF, PATH_TRAVERSAL, OPEN_REDIRECT, INSECURE_CODE.
Allowed severity values: CRITICAL, HIGH, MEDIUM, LOW.
Allowed method values: "GET", "POST", or null if not an exposed web route.
Allowed canary_type values: "reflected", "file_marker".

CRITICAL ACCURACY INSTRUCTIONS:
1. "sink_code": MUST be the actual, verbatim line(s) of code extracted directly from the target source file where the dangerous sink occurs. NEVER output placeholder text like "code snippet" or "sink_code".
2. "line_number": MUST be the exact line number where the vulnerable call or sink appears in the file.
3. "endpoint": If the vulnerability is inside an HTTP web handler (e.g., Flask/FastAPI route), provide the route path (e.g. "/fetch"). If the file is a unit test, script, or library without HTTP routes, set "endpoint": null and "method": null. Never output placeholders like "/vulnerable-route" or "GET | POST".
4. If no genuine logic vulnerabilities are found, return an empty array [].
5. Output ONLY valid JSON without markdown conversational wrapping.
"""


class HunterAgent(BaseAgent):
    """Identifies business logic and unexpressed taint flaws via LLM."""

    def __init__(self, target_dir: Path | str, config=None):
        super().__init__(config)
        self.target_dir = Path(target_dir).resolve()
        self.route_mapper = RouteMapper(self.target_dir)

    async def hunt(self, file_paths: Optional[list[Path | str]] = None) -> list[Finding]:
        """Scan target files with AI Hunter and propose findings."""
        if file_paths is None:
            file_paths = list(self.target_dir.rglob("*.py"))

        ignored_parts = {
            "__pycache__",
            ".venv",
            "venv",
            "env",
            ".env",
            "node_modules",
            ".git",
            ".pytest_cache",
            "site-packages",
        }

        findings: list[Finding] = []
        for file_path in file_paths:
            path = Path(file_path)
            if not path.is_file():
                continue

            # Skip hidden folders, virtualenvs, and pycache
            if any(part in ignored_parts or (part.startswith(".") and part != ".") for part in path.parts):
                continue

            # Skip very large files (> 60KB) to prevent CPU token timeouts
            try:
                if path.stat().st_size > 60_000:
                    continue
                content = path.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue

            # Limit prompt context to first 4000 characters if exceptionally long
            if len(content) > 4000:
                content = content[:4000] + "\n# ... (truncated for analysis)\n"

            user_prompt = f"File: {path.name}\nSource Code:\n```python\n{content}\n```"
            response_text = await self.call_llm(
                system_prompt=HUNTER_SYSTEM_PROMPT,
                user_prompt=user_prompt,
            )

            parsed_items = self._parse_json_response(response_text)
            for item in parsed_items:
                f = self._create_finding(item, path)
                if f:
                    findings.append(f)

        return findings

    def _parse_json_response(self, text: str) -> list[dict]:
        """Extract JSON array from LLM response with fence & bracket resilience."""
        text = text.strip()

        # Try parsing within markdown fences
        if "```" in text:
            parts = text.split("```")
            for p in parts:
                cleaned = p.strip()
                if cleaned.startswith("json"):
                    cleaned = cleaned[4:].strip()
                try:
                    data = json.loads(cleaned)
                    if isinstance(data, list):
                        return data
                    elif isinstance(data, dict):
                        return data.get("findings", [data])
                except Exception:
                    continue

        # Try finding [ ... ]
        start = text.find("[")
        end = text.rfind("]")
        if start != -1 and end > start:
            try:
                data = json.loads(text[start:end+1])
                if isinstance(data, list):
                    return data
            except Exception:
                pass

        try:
            data = json.loads(text)
            if isinstance(data, list):
                return data
            elif isinstance(data, dict):
                return data.get("findings", [data])
        except Exception:
            pass
        return []

    def _resolve_sink_code(self, raw_sink: str, file_path: Path, line_number: int) -> str:
        """Resolve authentic sink code from source file if raw sink is a placeholder or empty."""
        placeholder_strings = {
            "",
            "code snippet",
            "code_snippet",
            "snippet",
            "...",
            "none",
            "n/a",
            "null",
            "sink_code",
            "code sink",
            "placeholder",
            "exact vulnerable line(s) of code extracted directly from the source file",
        }
        cleaned = raw_sink.strip().strip("<>\"'").lower()
        is_placeholder = cleaned in placeholder_strings or "code snippet" in cleaned

        file_lines = []
        if file_path.is_file():
            try:
                file_lines = file_path.read_text(encoding="utf-8", errors="ignore").splitlines()
            except Exception:
                file_lines = []

        # If raw_sink is not a placeholder and appears valid, preserve it
        if not is_placeholder and raw_sink:
            return raw_sink

        # Extract authentic sink line(s) directly from disk at line_number
        if file_lines and 1 <= line_number <= len(file_lines):
            target_line = file_lines[line_number - 1].strip()
            # If the line is short (closing paren or continuation) and there's a previous line, include context
            if len(target_line) < 4 and line_number > 1:
                prev_line = file_lines[line_number - 2].strip()
                return f"{prev_line}\n{target_line}"
            return target_line

        return "" if is_placeholder else raw_sink

    def _create_finding(self, item: dict, file_path: Path) -> Optional[Finding]:
        """Convert LLM item into ScanneX Finding with Canary Probe Spec."""
        vuln_type = str(item.get("vuln_type", "LOGIC_FLAW")).strip().upper()
        if "|" in vuln_type:
            vuln_type = vuln_type.split("|")[0].strip()

        try:
            line_num = int(item.get("line_number", 1))
        except (ValueError, TypeError):
            line_num = 1

        cwe = str(item.get("cwe", "CWE-699")).strip()
        severity_str = str(item.get("severity", "HIGH")).strip().upper()
        if "|" in severity_str:
            severity_str = severity_str.split("|")[0].strip()
        
        severity_map = {
            "CRITICAL": Severity.CRITICAL,
            "HIGH": Severity.HIGH,
            "MEDIUM": Severity.MEDIUM,
            "LOW": Severity.LOW,
        }
        severity = severity_map.get(severity_str, Severity.HIGH)

        canary_type_str = str(item.get("canary_type", "reflected")).strip().lower()
        canary_type = CanaryType.FILE_MARKER if canary_type_str == "file_marker" else CanaryType.REFLECTED

        # Relativize path
        try:
            rel_path = str(file_path.relative_to(self.target_dir))
        except ValueError:
            rel_path = str(file_path)

        # Resolve authentic sink code directly from file on disk if missing or placeholder
        raw_sink = str(item.get("sink_code", "")).strip()
        sink_code = self._resolve_sink_code(raw_sink, file_path, line_num)

        # Endpoint and method sanitization / route mapping
        endpoint = str(item.get("endpoint") or "").strip()
        method = str(item.get("method") or "GET").strip().upper()
        if "|" in method:
            method = method.split("|")[0].strip()
        if method not in ("GET", "POST", "PUT", "DELETE", "PATCH"):
            method = "GET"

        param_name = str(item.get("param_name") or "q").strip()

        placeholder_endpoints = {
            "",
            "/vulnerable-route",
            "vulnerable-route",
            "/endpoint",
            "endpoint",
            "/path/to/endpoint",
            "null",
            "none",
        }

        # Check RouteMapper to resolve real HTTP route
        route = self.route_mapper.find_route_for_line(file_path, line_num)
        if route:
            endpoint = route.endpoint
            if route.methods:
                method = route.methods[0]
            if route.param_names and param_name in ("q", "parameter_name", ""):
                param_name = route.param_names[0]
        elif endpoint.lower() in placeholder_endpoints:
            endpoint = ""

        # Construct probe spec only if an accessible route exists
        probe_spec = None
        if endpoint and endpoint.lower() not in placeholder_endpoints:
            canary_token = f"SCANX_CANARY_{uuid.uuid4().hex[:8].upper()}"
            params = {}
            data = {}
            file_marker_path = None

            if canary_type == CanaryType.FILE_MARKER or "COMMAND" in vuln_type:
                temp_dir = Path(tempfile.gettempdir())
                marker_name = f"{canary_token.lower()}.txt"
                file_marker_path = str(temp_dir / marker_name)
                payload = f"127.0.0.1 & echo canary > {file_marker_path}"
            elif "SSTI" in vuln_type:
                canary_token = "9799547"
                payload = "{{ 1337 * 7331 }}"
            elif "SQL" in vuln_type:
                payload = f"' UNION SELECT 1, '{canary_token}', 'admin'--"
            else:
                payload = canary_token

            if method == "POST":
                data[param_name] = payload
            else:
                params[param_name] = payload

            probe_spec = ProbeSpec(
                endpoint=endpoint,
                method=method,
                params=params,
                data=data,
                canary_type=canary_type,
                canary_token=canary_token,
                file_marker_path=file_marker_path,
            )

        title = item.get("title", f"AI Hunter: {vuln_type} in {file_path.name}")
        if "|" in title and len(title) > 60:
            title = f"AI Hunter: {vuln_type} in {file_path.name}"

        finding = Finding(
            file_path=rel_path,
            line_number=line_num,
            vuln_type=vuln_type,
            cwe=cwe,
            severity=severity,
            title=title,
            description=item.get("description", "Vulnerability detected by AI Hunter agent."),
            sink_code=sink_code,
            source="ai_hunter",
            status=FindingStatus.NEEDS_VALIDATION,
            probe_spec=probe_spec,
        )
        finding.add_trace(f"AI Hunter identified potential {vuln_type} at line {line_num}")
        return finding

    def _mock_response(self, system_prompt: str, user_prompt: str) -> str:
        """Deterministic mock response discovering logic flaws in sample code."""
        # Inspect user prompt for common vulnerability patterns
        mock_findings = []
        if "render_template_string" in user_prompt:
            mock_findings.append({
                "file_path": "app.py",
                "line_number": 35,
                "vuln_type": "SSTI",
                "cwe": "CWE-94",
                "severity": "CRITICAL",
                "title": "Server-Side Template Injection via render_template_string",
                "description": "User-supplied template variable passed unescaped to render_template_string.",
                "sink_code": "return render_template_string(template)",
                "endpoint": "/render",
                "method": "GET",
                "param_name": "name",
                "canary_type": "reflected",
            })
        if "os.system" in user_prompt or "subprocess.Popen" in user_prompt:
            mock_findings.append({
                "file_path": "app.py",
                "line_number": 52,
                "vuln_type": "COMMAND_INJECTION",
                "cwe": "CWE-78",
                "severity": "CRITICAL",
                "title": "Remote Command Execution via unsanitized system call",
                "description": "User parameter concatenated directly into shell execution string.",
                "sink_code": "os.system(cmd)",
                "endpoint": "/tools/ping",
                "method": "POST",
                "param_name": "target",
                "canary_type": "file_marker",
            })

        return json.dumps(mock_findings, indent=2)
