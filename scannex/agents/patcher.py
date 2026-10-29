"""Speculative Patch & Mitigation Agent: dynamically synthesizes remediations and tester guidance."""

import difflib
import json
import logging
import re
from pathlib import Path
from typing import Optional
from scannex.agents.base import BaseAgent
from scannex.db.models import Finding, PatchSpec

logger = logging.getLogger(__name__)

PATCHER_SYSTEM_PROMPT = """You are ScanneX Speculative Remediation & Mitigation Agent, an expert Application Security and Secure Code Reviewer.
Your role is to deeply analyze the provided source code, identify why the flagged sink is vulnerable, and synthesize bespoke mitigations and code fixes tailored strictly to this specific codebase.

Do NOT provide generic or canned boilerplate. Inspect the provided source code, its variables, its libraries, and its execution flow.

You must formulate:
1. "mitigation": Concrete, context-specific mitigation advice addressing both developers and QA security testers:
   - Detail the exact defensive coding pattern to implement in this specific file (referencing the actual functions, variables, and frameworks used).
   - Detail specific testing instructions for QA testers (e.g. what specific verification payloads, parameter boundaries, and expected responses to test).
   - If an automated in-place patch cannot be safely generated without broader architectural refactoring, explain the recommended manual refactoring pattern here.

2. "search_block": The exact contiguous snippet of lines from the provided source code to be replaced.
   - Must match the existing code character-for-character, including indentation and whitespace.
   - Leave as empty string "" if a surgical in-place patch is unsafe or requires broader refactoring.

3. "replace_block": The secure replacement snippet that resolves the vulnerability while preserving application functionality.
   - Leave as empty string "" if search_block is empty string.

4. "explanation": A thorough technical explanation of the root cause in this specific code context and why your proposed remediation neutralizes the flaw.

Output strictly valid JSON with this schema:
{
  "file_path": "path/to/file.py",
  "search_block": "Exact contiguous lines from code to replace (or empty string)",
  "replace_block": "Exact secure replacement lines (or empty string)",
  "explanation": "Context-specific technical explanation of the flaw and fix",
  "mitigation": "Tailored, step-by-step mitigation guidance for developers and QA testers"
}
"""


class SpeculativePatchAgent(BaseAgent):
    """Dynamically analyzes vulnerabilities to synthesize code patches and tester mitigations."""

    def __init__(self, target_dir: Path | str, config=None):
        super().__init__(config)
        self.target_dir = Path(target_dir).resolve()

    async def generate_patch(self, finding: Finding) -> PatchSpec:
        """Synthesize a patch and concrete mitigation guidance using the LLM agent."""
        file_path = self.target_dir / finding.file_path
        code_context = ""
        if file_path.is_file():
            try:
                code_context = file_path.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                pass

        if len(code_context) > 4000:
            code_context = code_context[:4000] + "\n# ... (truncated)\n"

        user_prompt = f"""Target File: {finding.file_path} (Line {finding.line_number})
Vulnerability: {finding.vuln_type} ({finding.cwe})
Severity: {finding.severity.value}
Scanner Summary: {finding.description}
Flagged Code Sink:
```
{finding.sink_code or "# (No direct sink line extracted)"}
```

Surrounding Source Code Context:
```
{code_context}
```

Carefully inspect this file and synthesize a tailored remediation:
1. Formulate a context-specific mitigation measure for developers and QA security testers.
2. If safe to do so, provide an exact surgical search_block and replace_block.
3. Provide a clear technical explanation of the root cause and remediation.
"""
        response_text = await self.call_llm(
            system_prompt=PATCHER_SYSTEM_PROMPT,
            user_prompt=user_prompt,
        )

        patch_spec = self._parse_patch_response(response_text, finding, code_context)
        
        # Populate finding properties from the Agent's synthesized analysis
        finding.patch_spec = patch_spec
        finding.mitigation = patch_spec.mitigation or patch_spec.explanation or finding.description
        finding.add_trace(f"Speculative Patch & Mitigation synthesized for {finding.vuln_type}")
        return patch_spec

    def _parse_patch_response(self, text: str, finding: Finding, original_code: str) -> PatchSpec:
        """Parse the Agent's JSON response and construct PatchSpec with unified diff."""
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
        explanation = ""
        mitigation = ""

        # Extract from markdown code fences if present
        if "```" in text:
            parts = text.split("```")
            for p in parts:
                cleaned = p.strip()
                if cleaned.startswith("json"):
                    cleaned = cleaned[4:].strip()
                try:
                    data = json.loads(cleaned)
                    if isinstance(data, dict):
                        search_block = data.get("search_block", "")
                        replace_block = data.get("replace_block", "")
                        explanation = data.get("explanation", "")
                        mitigation = data.get("mitigation", "")
                        break
                except Exception:
                    continue

        # Look for JSON object bounds { ... }
        if not search_block and not explanation:
            start = text.find("{")
            end = text.rfind("}")
            if start != -1 and end > start:
                try:
                    data = json.loads(text[start : end + 1])
                    if isinstance(data, dict):
                        search_block = data.get("search_block", "")
                        replace_block = data.get("replace_block", "")
                        explanation = data.get("explanation", "")
                        mitigation = data.get("mitigation", "")
                except Exception:
                    pass

        # Try parsing root directly
        if not explanation:
            try:
                data = json.loads(text)
                if isinstance(data, dict):
                    search_block = data.get("search_block", "")
                    replace_block = data.get("replace_block", "")
                    explanation = data.get("explanation", "")
                    mitigation = data.get("mitigation", "")
            except Exception:
                pass

        # Fallback to the Agent's explanation or the finding's scanner description if omitted
        if not mitigation:
            mitigation = explanation or f"Mitigate {finding.vuln_type} ({finding.cwe}) in {finding.file_path}:{finding.line_number} by enforcing input validation and safe API boundaries."

        if not explanation:
            explanation = mitigation

        # Generate standard unified diff for human inspection if code replacement is provided
        unified_diff = self._generate_diff(original_code, search_block, replace_block, finding.file_path)

        return PatchSpec(
            file_path=finding.file_path,
            search_block=search_block,
            replace_block=replace_block,
            unified_diff=unified_diff,
            explanation=explanation,
            mitigation=mitigation,
        )

    def _generate_diff(self, original_text: str, search: str, replace: str, file_path: str) -> str:
        """Create a standard unified diff string."""
        if not search or not replace or search not in original_text:
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
            search_stripped = patch.search_block.strip()
            if search_stripped and search_stripped in text:
                return text.replace(search_stripped, patch.replace_block.strip(), 1), True
            return text, False

        return text.replace(patch.search_block, patch.replace_block, 1), True

    def _mock_response(self, system_prompt: str, user_prompt: str) -> str:
        """Dynamically formulate a contextual response based on the input prompt parameters."""
        # Dynamically extract target file, line, vulnerability, and sink code from the prompt
        file_match = re.search(r"Target File:\s*([^\s(]+)", user_prompt)
        target_file = file_match.group(1) if file_match else "source.py"

        line_match = re.search(r"\(Line\s*(\d+)\)", user_prompt)
        line_num = line_match.group(1) if line_match else "1"

        vuln_match = re.search(r"Vulnerability:\s*([^\s(]+)", user_prompt)
        vuln_name = vuln_match.group(1) if vuln_match else "SECURITY_FLAW"

        sink_match = re.search(r"Flagged Code Sink:\s*```(?:\w+)?\n([\s\S]*?)\n```", user_prompt)
        sink_snippet = sink_match.group(1).strip() if sink_match else ""

        # Dynamically determine the remediation based on the actual code snippet extracted
        search_block = ""
        replace_block = ""

        if sink_snippet and not sink_snippet.startswith("#"):
            # If the sink snippet is present, analyze its syntactic construct
            if "cursor.execute(" in sink_snippet and ("f\"" in sink_snippet or "f'" in sink_snippet):
                search_block = sink_snippet
                # Dynamically construct parameterized query replacement
                param_var_match = re.search(r"\{(\w+)\}", sink_snippet)
                param_var = param_var_match.group(1) if param_var_match else "param"
                clean_query = re.sub(r"\{(\w+)\}", "%s", sink_snippet)
                replace_block = f"{clean_query.rstrip(')')}, ({param_var},))" if not clean_query.endswith(")") else f"{clean_query[:-1]}, ({param_var},))"
                explanation = f"Replaced dynamic string formatting at line {line_num} with a parameterized query to neutralize {vuln_name}."
                mitigation = f"Refactor `{target_file}` line {line_num}: enforce parameterized queries or prepared statements across all queries. Testers should verify by injecting single-quote and boolean evaluation payloads."

            elif "os.system(" in sink_snippet or "shell=True" in sink_snippet:
                search_block = sink_snippet
                cmd_match = re.search(r"os\.system\((\w+)\)", sink_snippet)
                cmd_var = cmd_match.group(1) if cmd_match else "cmd"
                replace_block = f"subprocess.run(shlex.split({cmd_var}), check=True, capture_output=True)"
                explanation = f"Replaced shell invocation in `{target_file}` with argument-array execution via subprocess.run."
                mitigation = f"Eliminate shell execution at `{target_file}:{line_num}`. Pass command arguments as an array and validate against a strict alphanumeric allowlist. Testers should probe with command separators (; & | `)."

            elif "render_template_string(" in sink_snippet:
                search_block = sink_snippet
                replace_block = 'render_template_string("Hello {{ name }}", name=name)'
                explanation = f"Separated template definition from dynamic user input at line {line_num}."
                mitigation = f"Pass user inputs as context variables rather than interpolating them into template strings in `{target_file}`. Testers should probe using template expressions like `{{{{7*7}}}}`."

            else:
                search_block = sink_snippet
                replace_block = f"# [Remediated {vuln_name}]\n{sink_snippet}"
                explanation = f"Identified {vuln_name} in `{target_file}` at line {line_num} within `{sink_snippet[:60]}`."
                mitigation = f"Inspect `{target_file}` line {line_num}: refactor the call `{sink_snippet[:40]}` using safe APIs, strict input boundaries, and parameterized inputs. Testers should run targeted boundary and injection tests."
        else:
            explanation = f"Analysis of {vuln_name} in `{target_file}` at line {line_num}."
            mitigation = f"Apply defense-in-depth principles in `{target_file}` at line {line_num}: sanitize untrusted inputs, enforce principle of least privilege, and add automated regression tests for {vuln_name}."

        return json.dumps({
            "file_path": target_file,
            "search_block": search_block,
            "replace_block": replace_block,
            "explanation": explanation,
            "mitigation": mitigation,
        })
