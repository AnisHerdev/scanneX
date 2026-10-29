"""Data models for findings, probes, patches, and verification results."""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional
from pydantic import BaseModel, Field
import uuid


class FindingStatus(str, Enum):
    """Honest-by-design finding status ontology."""
    CONFIRMED_DYNAMIC = "confirmed_dynamic"
    VERIFIED_FIXED = "verified_fixed"
    CONFIRMED_STATIC = "confirmed_static"
    NEEDS_VALIDATION = "needs_validation"
    UNVERIFIED = "unverified"
    REJECTED = "rejected"


class Severity(str, Enum):
    """Standard vulnerability severity rating."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class CanaryType(str, Enum):
    """Type of deterministic canary oracle check."""
    REFLECTED = "reflected"
    FILE_MARKER = "file_marker"


class ProbeSpec(BaseModel):
    """Execution blueprint for a harmless canary probe."""
    endpoint: str = Field(description="Target HTTP path, e.g. /login or /query")
    method: str = Field(default="GET", description="HTTP verb: GET, POST, PUT, DELETE")
    headers: dict[str, str] = Field(default_factory=dict)
    params: dict[str, Any] = Field(default_factory=dict)
    data: dict[str, Any] = Field(default_factory=dict)
    json_body: Optional[dict[str, Any]] = None
    canary_type: CanaryType = Field(default=CanaryType.REFLECTED)
    canary_token: str = Field(description="Unique canary string to verify")
    file_marker_path: Optional[str] = Field(default=None, description="Path checked for file_marker canaries")
    timeout_sec: int = Field(default=5)


class ProbeResult(BaseModel):
    """Result returned by the deterministic sandbox oracle."""
    success: bool = False
    canary_tripped: bool = False
    status_code: Optional[int] = None
    response_snippet: Optional[str] = None
    error_message: Optional[str] = None
    execution_time_ms: float = 0.0
    sandbox_type: str = "subprocess"


class PatchSpec(BaseModel):
    """Speculative patch representation using robust search-and-replace blocks."""
    file_path: str
    search_block: str
    replace_block: str
    unified_diff: str = ""
    explanation: str = ""
    mitigation: str = ""
    applied_successfully: bool = False
    retest_verified: bool = False


class Finding(BaseModel):
    """Represents a discovered security finding with full evidence trace."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    file_path: str
    line_number: int = 1
    vuln_type: str
    cwe: str = "CWE-Unknown"
    severity: Severity = Severity.MEDIUM
    title: str
    description: str
    sink_code: str = ""
    source: str = "static_bandit"  # static_semgrep, static_bandit, ai_hunter
    status: FindingStatus = FindingStatus.NEEDS_VALIDATION
    verifier_notes: Optional[str] = None
    mitigation: str = ""
    probe_spec: Optional[ProbeSpec] = None
    probe_result: Optional[ProbeResult] = None
    patch_spec: Optional[PatchSpec] = None
    evidence_trace: list[str] = Field(default_factory=list)
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def add_trace(self, event: str) -> None:
        """Append an audit event to the evidence trace."""
        timestamp = datetime.now(timezone.utc).strftime("%H:%M:%S.%f")[:-3]
        self.evidence_trace.append(f"[{timestamp}] {event}")
        self.updated_at = datetime.now(timezone.utc).isoformat()
