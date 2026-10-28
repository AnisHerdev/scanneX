"""Deterministic Canary Oracle for ScanneX.

A zero-trust evaluation engine where a deterministic oracle—never the LLM—decides
whether a planted canary token was triggered.
"""

from pathlib import Path
import tempfile
from typing import Optional
import requests
from scannex.db.models import CanaryType, ProbeResult, ProbeSpec


class DeterministicOracle:
    """Evaluates probe execution outcomes against planted canaries."""

    def evaluate_http_response(
        self,
        probe_spec: ProbeSpec,
        response: Optional[requests.Response],
        sandbox_dir: Optional[Path] = None,
        error: Optional[Exception] = None,
        duration_ms: float = 0.0,
        sandbox_type: str = "subprocess",
    ) -> ProbeResult:
        """Deterministically determine if the probe tripped the planted canary."""
        if error is not None:
            return ProbeResult(
                success=False,
                canary_tripped=False,
                error_message=str(error),
                execution_time_ms=duration_ms,
                sandbox_type=sandbox_type,
            )

        if response is None:
            return ProbeResult(
                success=False,
                canary_tripped=False,
                error_message="No response received from sandbox target",
                execution_time_ms=duration_ms,
                sandbox_type=sandbox_type,
            )

        canary_tripped = False
        snippet = None

        if probe_spec.canary_type == CanaryType.REFLECTED:
            # Check response body and headers for exact canary token
            token = probe_spec.canary_token
            if token in response.text:
                canary_tripped = True
                # Extract surrounding context for evidence
                idx = response.text.find(token)
                start = max(0, idx - 40)
                end = min(len(response.text), idx + len(token) + 40)
                snippet = f"...{response.text[start:end]}..."
            else:
                for h_name, h_val in response.headers.items():
                    if token in h_val:
                        canary_tripped = True
                        snippet = f"Header {h_name}: {h_val}"
                        break

        elif probe_spec.canary_type == CanaryType.FILE_MARKER:
            # Deterministically verify file creation on the filesystem
            marker_path = probe_spec.file_marker_path
            if marker_path:
                mp = Path(marker_path)
                marker_name = mp.name
                
                # Check exact path
                if mp.exists():
                    canary_tripped = True
                    snippet = f"Planted canary file created: {mp}"
                    try:
                        mp.unlink()
                    except Exception:
                        pass
                # Check relative to sandbox_dir
                elif sandbox_dir and (sandbox_dir / marker_name).exists():
                    canary_tripped = True
                    snippet = f"Planted canary file created in sandbox: {marker_name}"
                    try:
                        (sandbox_dir / marker_name).unlink()
                    except Exception:
                        pass
                # Check in system temp
                elif (Path(tempfile.gettempdir()) / marker_name).exists():
                    canary_tripped = True
                    snippet = f"Planted canary file created in tempdir: {marker_name}"
                    try:
                        (Path(tempfile.gettempdir()) / marker_name).unlink()
                    except Exception:
                        pass

        return ProbeResult(
            success=True,
            canary_tripped=canary_tripped,
            status_code=response.status_code,
            response_snippet=snippet,
            execution_time_ms=duration_ms,
            sandbox_type=sandbox_type,
        )
