"""Adversarial Verifier agent: acts as defender/prosecutor to audit AI Hunter findings."""

import json
from pathlib import Path
from pydantic import BaseModel
from scannex.agents.base import BaseAgent
from scannex.db.models import Finding, FindingStatus


VERIFIER_SYSTEM_PROMPT = """You are ScanneX Adversarial Verifier, an expert code auditor playing the role of DEFENDER.
Your job is to rigorously review a proposed vulnerability finding from the AI Hunter and attempt to DISPROVE it.

Check for:
1. Input sanitization (e.g., int(x), html.escape(x), shlex.quote(x), parameterized queries, regex checks).
2. Framework security protections (CSRF tokens, auth decorators like @login_required, input length limits).
3. Dead code or unreachable paths.
4. Hallucinated APIs or non-existent sinks.

Be concise. Respond ONLY with valid JSON in this schema:
{
  "up_approved": true | false,
  "confidence": 0.0 to 1.0,
  "reason": "Brief explanation of why this finding is upheld or disproved",
  "sanitizer_found": "Name or snippet of sanitizer, or null if none"
}
"""


class VerificationResult(BaseModel):
    """Outcome of adversarial audit."""
    up_approved: bool
    confidence: float = 1.0
    reason: str
    sanitizer_found: str | None = None


class VerifierAgent(BaseAgent):
    """Evaluates AI Hunter findings to eliminate hallucinations before consolidation."""

    def __init__(self, target_dir: Path | str, config=None):
        super().__init__(config)
        self.target_dir = Path(target_dir).resolve()

    async def verify(self, finding: Finding) -> VerificationResult:
        """Adversarially evaluate whether a finding is genuine or disprovable."""
        file_path = self.target_dir / finding.file_path
        code_context = ""
        if file_path.is_file():
            try:
                code_context = file_path.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                pass

        if len(code_context) > 4000:
            code_context = code_context[:4000] + "\n# ... (truncated)\n"

        user_prompt = f"""Target File: {finding.file_path}
Reported Line: {finding.line_number}
Vulnerability Type: {finding.vuln_type}
Proposed Sink Code: {finding.sink_code}
Hunter Claim: {finding.description}

Full File Context:
```python
{code_context}
```
"""
        response_text = await self.call_llm(
            system_prompt=VERIFIER_SYSTEM_PROMPT,
            user_prompt=user_prompt,
        )

        result = self._parse_result(response_text)
        if not result.up_approved:
            finding.status = FindingStatus.REJECTED
            finding.verifier_notes = f"Disproved by Verifier: {result.reason}"
            finding.add_trace(f"Adversarial Verifier disproved finding: {result.reason}")
        else:
            finding.verifier_notes = f"Up-approved by Verifier: {result.reason}"
            finding.add_trace(f"Adversarial Verifier validated finding (confidence={result.confidence:.2f})")

        return result

    def _parse_result(self, text: str) -> VerificationResult:
        """Parse JSON verification output with fence & brace resilience."""
        text = text.strip()

        # Check in markdown blocks
        if "```" in text:
            parts = text.split("```")
            for p in parts:
                cleaned = p.strip()
                if cleaned.startswith("json"):
                    cleaned = cleaned[4:].strip()
                try:
                    data = json.loads(cleaned)
                    if isinstance(data, dict):
                        return VerificationResult(
                            up_approved=bool(data.get("up_approved", True)),
                            confidence=float(data.get("confidence", 0.9)),
                            reason=str(data.get("reason", "Verified plausible vulnerability")),
                            sanitizer_found=data.get("sanitizer_found"),
                        )
                except Exception:
                    continue

        # Look for { ... }
        start = text.find("{")
        end = text.rfind("}")
        if start != -1 and end > start:
            try:
                data = json.loads(text[start:end+1])
                if isinstance(data, dict):
                    return VerificationResult(
                        up_approved=bool(data.get("up_approved", True)),
                        confidence=float(data.get("confidence", 0.9)),
                        reason=str(data.get("reason", "Verified plausible vulnerability")),
                        sanitizer_found=data.get("sanitizer_found"),
                    )
            except Exception:
                pass

        try:
            data = json.loads(text)
            return VerificationResult(
                up_approved=bool(data.get("up_approved", True)),
                confidence=float(data.get("confidence", 0.9)),
                reason=str(data.get("reason", "Verified plausible vulnerability")),
                sanitizer_found=data.get("sanitizer_found"),
            )
        except Exception:
            return VerificationResult(
                up_approved=True,
                confidence=0.8,
                reason="Defaulting to plausible audit confirmation",
            )

    def _mock_response(self, system_prompt: str, user_prompt: str) -> str:
        """Deterministic mock response for offline verification."""
        # Check if the sink code or reported line has explicit sanitization
        prompt_lower = user_prompt.lower()
        if "shlex.quote" in prompt_lower or "html.escape" in prompt_lower or "int(target)" in prompt_lower or "@login_required" in user_prompt:
            return json.dumps({
                "up_approved": False,
                "confidence": 0.95,
                "reason": "Input is guarded by sanitization or authorization decorator.",
                "sanitizer_found": "sanitizer/auth check present",
            })

        # Up-approve genuine vulnerable patterns
        return json.dumps({
            "up_approved": True,
            "confidence": 0.92,
            "reason": "No sanitization or security controls found between tainted input and sink.",
            "sanitizer_found": None,
        })
