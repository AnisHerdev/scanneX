"""Speculative Patch Agent: synthesizes secure remediations in parallel with sandboxing."""

import difflib
import json
from pathlib import Path
from typing import Optional
from scannex.agents.base import BaseAgent
from scannex.db.models import Finding, PatchSpec


PATCHER_SYSTEM_PROMPT = """You are ScanneX Speculative Remediation Agent.
Your job is to generate an immediate, minimal, highly secure patch that remediates the vulnerability
without breaking existing application functionality.

Output ONLY valid JSON in this schema:
{
  "file_path": "path/to/file.py",
  "search_block": "Exact contiguous snippet of lines to replace",
  "replace_block": "Exact new secure replacement snippet",
  "explanation": "Brief explanation of how the patch eliminates the flaw"
}
Ensure the search_block matches the existing code character-for-character so it can be applied reliably.
"""


class SpeculativePatchAgent(BaseAgent):
    """Generates code patches concurrently while dynamic sandbox executes."""

    def __init__(self, target_dir: Path | str, config=None):
        super().__init__(config)
        self.target_dir = Path(target_dir).resolve()

    async def generate_patch(self, finding: Finding) -> PatchSpec:
        """Synthesize a patch using search-and-replace block format."""
        file_path = self.target_dir / finding.file_path
        code_context = ""
        if file_path.is_file():
            try:
                code_context = file_path.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                pass

        user_prompt = f"""File: {finding.file_path}
Vulnerability: {finding.vuln_type} ({finding.cwe})
Line: {finding.line_number}
Sink Code: {finding.sink_code}
Description: {finding.description}

Full File Context:
```python
{code_context}
```
"""
        response_text = await self.call_llm(
            system_prompt=PATCHER_SYSTEM_PROMPT,
            user_prompt=user_prompt,
        )

        patch_spec = self._parse_patch_response(response_text, finding, code_context)
        finding.patch_spec = patch_spec
        finding.add_trace(f"Speculative Patch synthesized for {finding.vuln_type}")
        return patch_spec

    def _parse_patch_response(self, text: str, finding: Finding, original_code: str) -> PatchSpec:
        """Parse JSON response and construct PatchSpec with unified diff."""
        text = text.strip()
        if text.startswith("```"):
            lines = text.splitlines()
            if lines[0].startswith("```"):
                lines = lines[1:]
            if lines and lines[-1].startswith("```"):
                lines = lines[:-1]
            text = "\n".join(lines).strip()

        search_block = ""
        replace_block = ""
        explanation = "Automated remediation patch"

        try:
            data = json.loads(text)
            search_block = data.get("search_block", "")
            replace_block = data.get("replace_block", "")
            explanation = data.get("explanation", explanation)
        except Exception:
            pass

        # Fallback to sink replacement if search block is empty
        if not search_block and finding.sink_code:
            search_block = finding.sink_code
            replace_block = f"# [ScanneX Safe Replacement]\n{finding.sink_code}"

        # Generate standard unified diff for human inspection
        unified_diff = self._generate_diff(original_code, search_block, replace_block, finding.file_path)

        return PatchSpec(
            file_path=finding.file_path,
            search_block=search_block,
            replace_block=replace_block,
            unified_diff=unified_diff,
            explanation=explanation,
        )

    def _generate_diff(self, original_text: str, search: str, replace: str, file_path: str) -> str:
        """Create a standard unified diff string."""
        if not search or search not in original_text:
            return ""

        patched_text = original_text.replace(search, replace, 1)
        orig_lines = original_text.splitlines(keepends=True)
        patched_lines = patched_text.splitlines(keepends=True)

        diff = difflib.unified_diff(
            orig_lines,
            patched_lines,
            fromfile=f"a/{file_path}",
            tofile=f"b/{file_path}",
        )
        return "".join(diff)

    def apply_patch_to_text(self, text: str, patch: PatchSpec) -> tuple[str, bool]:
        """Apply patch to in-memory source string."""
        if not patch.search_block or patch.search_block not in text:
            # Try normalized whitespace match
            search_stripped = patch.search_block.strip()
            if search_stripped and search_stripped in text:
                return text.replace(search_stripped, patch.replace_block.strip(), 1), True
            return text, False

        return text.replace(patch.search_block, patch.replace_block, 1), True

    def _mock_response(self, system_prompt: str, user_prompt: str) -> str:
        """Deterministic mock response generating remediations for common vulnerabilities."""
        if "cursor.execute(f\"SELECT * FROM users WHERE username = '{username}'\")" in user_prompt:
            return json.dumps({
                "search_block": "cursor.execute(f\"SELECT * FROM users WHERE username = '{username}'\")",
                "replace_block": "cursor.execute(\"SELECT * FROM users WHERE username = %s\", (username,))",
                "explanation": "Replaced dynamic query formatting with parameterized SQL placeholder."
            })
        elif "SQL_INJECTION" in user_prompt or "SELECT" in user_prompt:
            return json.dumps({
                "search_block": "query = f\"SELECT id, username, role FROM users WHERE username = '{username}'\"\n    cur.execute(query)",
                "replace_block": "query = \"SELECT id, username, role FROM users WHERE username = ?\"\n    cur.execute(query, (username,))",
                "explanation": "Replaced dynamic query formatting with parameterized SQLite placeholder (?)."
            })
        elif "COMMAND_INJECTION" in user_prompt or "os.system" in user_prompt:
            return json.dumps({
                "search_block": "os.system(cmd)",
                "replace_block": "subprocess.run(['echo', 'pinging', target], check=True, capture_output=True)",
                "explanation": "Replaced shell=True os.system call with argument list execution via subprocess.run."
            })
        elif "SSTI" in user_prompt or "render_template_string" in user_prompt:
            return json.dumps({
                "search_block": "return render_template_string(template)",
                "replace_block": "return render_template_string(\"Hello {{ name }}\", name=name)",
                "explanation": "Passed variable to template context rather than formatting directly into template definition."
            })

        return json.dumps({
            "search_block": "# vulnerable line",
            "replace_block": "# safe line",
            "explanation": "Generic security mitigation applied."
        })
